

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>
#include <rte_timer.h>

#include "arp.h"

#define ENABLE_SEND        1
#define ENABLE_ARP         1
#define ENABLE_ICMP        1
#define ENABLE_ARP_REPLY   1

#define ENABLE_DEBUG       1
#define ENABLE_TIMER       1


#define NUM_MBUFS (4096-1)

#define BURST_SIZE    32
#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6
// 10ms at 2Ghz   20000000ULL = 10ms


#if ENABLE_SEND

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 79, 201); // dpdk端口设置的IP

static uint32_t gSrcIp; // 全局的一对一 如果多个这种写法就不行了
static uint32_t gDstIp;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

static uint16_t gSrcPort;
static uint16_t gDstPort;

#endif

#if ENABLE_ARP_REPLY
// arp Broadcast 广播mac地址
static uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
#endif
// 定义一个端口的id表示的是 绑定的网卡id
int gDpdkPortId = 0;
// 设置端口配置信息
static const struct rte_eth_conf port_conf_default = {
        .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

static void ng_init_port(struct rte_mempool *mbuf_pool) {
    // 检测端口是否可用 dpdk 绑定了多少个网卡 这里应该是多少个
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if (nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    }
    // 获取默认的第一个网口
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info); // 第一个网口信息

    const int num_rx_queues = 1;// 接受 最多可以设置八个 因为有八个CPU当前机器
    const int num_tx_queues = 1;// 发送 暂时这个版本 不发送数据 先设置0
    struct rte_eth_conf port_conf = port_conf_default;
    // 多队列网卡的意思是 设置这个端口的配置信息
    // 用于配置以太网设备的全局参数。它通常在设置特定队列之前调用，用于初始化和配置设备的总体属性和行为
    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);
    // 用于配置和初始化特定 RX 队列的参数，包括 RX 描述符的数量、NUMA 节点和内存池。
    // 127 指的是可以堆积这么多 队列里面的数量是128
    if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 1024,
                               rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");

    }
#if ENABLE_SEND
    // 接收多大 发送多大
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    // 第二个参数 对应的是那个队列 第三个参数对应的队列最大承载多少
    // Invalid value for nb_tx_desc(=128), should be: <= 4096, >= 512, and a product of 1 调整为1024
    if (rte_eth_tx_queue_setup(
            gDpdkPortId, 0, 1024,
            rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
        rte_exit(EXIT_FAILURE, "发送队列设置失败\n");
    }
#endif
    // 设置完之后 启动接收队列
    if (rte_eth_dev_start(gDpdkPortId) < 0) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }


}

static int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len) {
    // dpdp从最开始就创建了一个内存池
    // encode 打包成udp的包
    // 1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *) msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);

    // 两个字节以上都转 本地字节序 转换到 网络字节序
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
    // 2 ipv4hdr 偏移
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *) (msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    // htons 表示将16位的 主机字节序(人类可阅读的模式) 转换 为网络字节序
    // ipv4头的total_length表示 ip层以及一下的所有的总字节数(包含ip本身字节-不包含以太网字节数据)
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64; // ttl = 64 默认值 如果写0  应该发不出去包
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = gSrcIp;
    ip->dst_addr = gDstIp;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    // 3 udphdr 偏移
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *) (msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = gSrcPort;
    udp->dst_port = gDstPort;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);
    // 从  (udp + 1) 位置 复制udplen个字节
    rte_memcpy((uint8_t *) (udp + 1), data, udplen);
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp); // l4表示第四层

    // 打印测试
    struct in_addr addr;
    addr.s_addr = gSrcIp;
    addr.s_addr = gDstIp;
    char src_mac_str[RTE_ETHER_ADDR_FMT_SIZE];
    char dst_mac_str[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(src_mac_str, RTE_ETHER_ADDR_FMT_SIZE, &eth->s_addr);
    rte_ether_format_addr(dst_mac_str, RTE_ETHER_ADDR_FMT_SIZE, &eth->d_addr);

    // ntohs 表示将16位的 网络字节序 转换 为主机字节序(人类可阅读的模式)
    printf("发送方 --> src: %s:%s:%d", src_mac_str, inet_ntoa(addr), ntohs(udp->src_port));
    printf("-->dst: %s:%s:%d\n", dst_mac_str, inet_ntoa(addr), ntohs(udp->dst_port));
    return 0;
}

/**
 * 该方法组装一个udp需要多大的数据空间
 * @param mbuf_pool
 * @param data
 * @param length
 * @return
 */
// mbuf 需要从内存池中获取 组装数据
static struct rte_mbuf *ng_send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length) {
    // mempool --> mbuf 从内存池中获取一个mbuf ,使用内存池最小的单位是 mbuf
    // 从 内存池一次性拿多少数据出来
    // 14(以太网头大小) + 20(IPV4头大小) + 8(UDP头大小) + (剩余应用层数据大小.....)
    // const static
    // 没有减8看情况应该是一个bug
    const unsigned total_len = 42 + length - 8; // 可能需要减8(length包含了UDP头大小)
    // 分配内存 为什么的内存为什么没有设置大小，因为只需要在内存池中分配从哪里开始使用内存，大小在mbuf中后续设置使用多少即可
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    // 分配失败
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc 分配内存失败\n");
    }

    mbuf->pkt_len = total_len; // 包的大小
    mbuf->data_len = total_len; // 一般设置同样大就可以 如果不同可能根据业务调整即可
    // 从mbuf里面把对应的数据 请注意mbuf是一个结构体 这个结构体和具体存储的数据是分离的 需要拿到存储数据具体的位置
    // 然后提供一个方法可以实现
    uint8_t * pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *); // 强转数据
    // 编码设置成->udp需要的数据格式规范
    ng_encode_udp_pkt(pktdata, data, total_len);

    return mbuf;
}

#if ENABLE_ARP

static int ng_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
    // 1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *) msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    // rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    if (!strncmp((const char *) dst_mac, (const char *) gDefaultArpMac, RTE_ETHER_ADDR_LEN)) {
        // 该代码貌似有问题 wireshark抓包显示 广播地址应该就是 Destination: Broadcast (ff:ff:ff:ff:ff:ff) 而不是 0吧?
        // uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};
        rte_memcpy(eth->d_addr.addr_bytes, gDefaultArpMac, RTE_ETHER_ADDR_LEN);
    } else {
        rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    }
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);
    // 2 arp
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *) (eth + 1);
    arp->arp_hardware = htons(1);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    // 软件地址说得是ip地址 硬件地址说得是mac地址
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(uint32_t);
    arp->arp_opcode = htons(opcode); // response=RTE_ARP_OP_REPLY

    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    arp->arp_data.arp_sip = sip; // 发件人
    arp->arp_data.arp_tip = dip; // 目标人
    return 0;
}

static struct rte_mbuf *
ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "ng_send_arp rte_pktmbuf_alloc 分配内存失败\n");
    }
    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t * pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ng_encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);
    return mbuf;
}

#endif


#if ENABLE_ICMP

// 处理imcp的checksum 该方法在网络rfc协议中可以查到对应的算法
static uint16_t ng_checksum(uint16_t *addr, int count) {
    register long sum = 0;
    while (count > 1) {
        sum += *(unsigned short *) addr++;
        count -= 2;
    }
    if (count > 0) {
        sum += *(unsigned char *) addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}

static int ng_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac,
                              uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {
    // 1 ether
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *) msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
    // 2 ip
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *) (msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    // htons 表示将16位的 主机字节序(人类可阅读的模式) 转换 为网络字节序
    // ipv4头的total_length表示 ip层以及一下的所有的总字节数(包含ip本身字节-不包含以太网字节数据)
    ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64; // ttl = 64 默认值 如果写0  应该发不出去包
    ip->next_proto_id = IPPROTO_ICMP;
    ip->src_addr = sip;
    ip->dst_addr = dip;
    // 计算ip的checksum
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    // 3 icmp
    struct rte_icmp_hdr *icmp =
            (struct rte_icmp_hdr *) (msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY; // 应答
    icmp->icmp_code = 0;
    icmp->icmp_ident = id;
    icmp->icmp_seq_nb = seqnb;

    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = ng_checksum((uint16_t *) icmp, sizeof(struct rte_icmp_hdr));
    return 0;
}


static struct rte_mbuf *ng_send_icmp(
        struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {
    // mempool --> mbuf 从内存池中获取一个mbuf ,使用内存池最小的单位是 mbuf
    // 从 内存池一次性拿多少数据出来
    const unsigned total_length =
            sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);
    // 开辟一个mbuf
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "icmp数据包分配内存失败rte_pktmbuf_alloc\n");
    }
    // 设置一下大小
    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;
    // 从mbuf里面把对应的数据 请注意mbuf是一个结构体 这个结构体和具体存储的数据是分离的 需要拿到存储数据具体的位置
    // 然后提供一个方法可以实现
    uint8_t * pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *); // 强转数据
    // 编码设置成->imcp需要的数据格式规范
    ng_encode_icmp_pkt(pkt_data, dst_mac, sip, dip, id, seqnb);
    return mbuf;
}

#endif


static void print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr) {
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s", name, buf);
}


#if ENABLE_TIMER

/**
 * 定时器回调函数 多久执行一次
 * (__attribute__((unused)) 意思是编译时不在警告改变量没有使用
 * @param tim
 * @param arg
 */
static void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg) {
    printf("执行了定时任务 arp_request_timer_cb 方法  ...............\n");
    // 传递的是内存池
    // 定时发送arp请求
    struct rte_mempool *mbuf_pool = (struct rte_mempool *) arg;
#if 0
    struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, ahdr->arp_data.arp_sha.addr_bytes,
        ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

    rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
    rte_pktmbuf_free(arpbuf);
#endif
    int i = 0;
    // 局域网里每一台机器都发一次
    for (i = 0; i < 254; i++) {
        // for (i = 9; i <= 9; i++) {
        uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));
        // struct in_addr addr;
        // addr.s_addr = dstip;
        // printf("arp_request_timer_cb arp ---> src: %s \n", inet_ntoa(addr));

        struct rte_mbuf *arpbuf = NULL;
        uint8_t * dstmac = ng_get_dst_macaddr(dstip);
        if (dstmac == NULL) {
            arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, gLocalIp, dstip);
        } else {
            arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac, gLocalIp, dstip);
        }
        rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
        rte_pktmbuf_free(arpbuf);
    }
}

#endif

/**
 * 接受数据功能
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char *argv[]) {
    // DPDK 的环境初始化
    // 检查大页巨页 hugepage 有没有进行设置
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }
    // 初始化内存池 DPDK 一个进程确定一个内存池 内存会放在这个变量中
    // 设置4K 8K都是可以的 这里我们设置一个特殊的值 不去满足2的N次方 比如设置4096-1的好处  小于4k的放在4K里面 大于4K的 放在另外大于4K的地方
    // 初始化内存池
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
            "mbuf pool", NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }
    // 初始化获取网卡网口驱动信息
    ng_init_port(mbuf_pool);
    // 获取绑定的网口mac地址
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *) gSrcMac);
#if ENABLE_TIMER
    // rte_timer 初始化
    rte_timer_subsystem_init();
    // 定义一个 初始化
    struct rte_timer arp_timer;
    rte_timer_init(&arp_timer);
    // 获取它的频率
    uint64_t hz = rte_get_timer_hz();
    unsigned lcore_id = rte_lcore_id();
    // PERIODICAL 代表重复的触发
    rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);
#endif
    while (1) {
        // 接受数据的时候 包的数据量最大可以写入128个
        // 如果超过128 可能会出错 机器网卡可能会重启 、丢弃还是重启 还不太确定 ，超出了机器可能会重启 或者宕机 具体要看什么情况
        struct rte_mbuf *mbufs[BURST_SIZE]; // 也可以设置大一点128个
        // 通过该方法接受网卡数据
        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
        if (num_recvd > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        }

        unsigned i = 0;
        for (i = 0; i < num_recvd; i++) {

            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
#if ENABLE_ARP
            if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                // 偏移一个以太网的数据包的大小
                struct rte_arp_hdr *arp_hdr =
                        rte_pktmbuf_mtod_offset(mbufs[i], struct rte_arp_hdr*, sizeof(struct rte_ether_hdr));
                struct in_addr addr;
                // 调试代码
                addr.s_addr = arp_hdr->arp_data.arp_sip; // 发送方的IP
                printf("arp ---> 发送方IP: %s \n", inet_ntoa(addr));
                // 发送的目标IP
                addr.s_addr = arp_hdr->arp_data.arp_tip; // 某个机器发送的目标IP
                printf("arp ---> src: %s ", inet_ntoa(addr));
                addr.s_addr = gLocalIp;
                printf(" local: %s \n", inet_ntoa(addr));
                // 如果目标IP和本机IP相同则处理(说明在广播获取本机IP以及mac地址) 返回自己的mac地址
                // 目标IP发送本机的时候才处理 如果没有if的判断就是一个arp攻击
                if (arp_hdr->arp_data.arp_tip == gLocalIp) {
                    if (arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
                        // arp发送 请求的代码
                        struct rte_mbuf *arpmbuf = ng_send_arp(
                                mbuf_pool, RTE_ARP_OP_REPLY, arp_hdr->arp_data.arp_sha.addr_bytes,
                                arp_hdr->arp_data.arp_tip, arp_hdr->arp_data.arp_sip);
                        rte_eth_tx_burst(gDpdkPortId, 0, &arpmbuf, 1);
                        rte_pktmbuf_free(arpmbuf);
                        rte_pktmbuf_free(mbufs[i]);
                        // rte_cpu_to_be_16 16位整数从主机字节序转换为网络字节序（大端序）
                    } else if (arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
                        // 对方回应了 arp发送 响应的代码
                        uint8_t * hwaddr = ng_get_dst_macaddr(arp_hdr->arp_data.arp_sip);
                        printf("arp --> 回应数据包 RTE_ARP_OP_REPLY \n");
                        struct arp_table *table = arp_table_instance();
                        if (hwaddr == NULL) {
                            printf("arp --> ng_get_dst_macaddr(arp_hdr->arp_data.arp_sip) == NULL \n");
                            struct arp_entry *entry = rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
                            if (entry) {
                                // 初始化值设置0
                                memset(entry, 0, sizeof(struct arp_entry));
                                // 记录发送方的ip地址
                                entry->ip = arp_hdr->arp_data.arp_sip;
                                // 记录发送方的mac地址
                                rte_memcpy(entry->hwaddr, arp_hdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
                                entry->type = ARP_ENTRY_STATUS_DYNAMIC; // 动态
                                // 提高
                                LL_ADD(entry, table->entries);
                                // 展开后的代码
                                // entry->prev = ((void *) 0);
                                // entry->next = table->entries;
                                // if (table->entries != ((void *) 0)) {
                                //     table->entries->prev = entry;
                                // }
                                // table->entries = entry;
                                table->count++;
                            }
                        }
#if ENABLE_DEBUG
                        struct arp_entry *iter;
                        for (iter = table->entries; iter != NULL; iter = iter->next) {
                            struct in_addr addr;
                            addr.s_addr = iter->ip;
                            print_ethaddr("arp table --> mac: ", (struct rte_ether_addr *) iter->hwaddr);
                            printf(" ip: %s \n", inet_ntoa(addr));
                        }
#endif
                    }
                    continue;
                }
            }
#endif
            // if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) { // 测试代码后续删除
            //     continue;
            // }
            if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }

            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *,
                                                                 sizeof(struct rte_ether_hdr));

            if (iphdr->next_proto_id == IPPROTO_UDP) {

                // struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *) (iphdr + 1);
                // 上一行代码修正版
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *) ((char *) iphdr + sizeof(struct rte_ipv4_hdr));
                if (ntohs (udphdr->src_port) != 8888) { // 做测试用的 可以后期删除
                    continue;
                }

#if ENABLE_SEND //
                rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

                rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
                rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));

                rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
                rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));
#endif

                // 网络字节顺什么时候转换 两个字节以上包含两个字节
                uint16_t length = ntohs(udphdr->dgram_len);
                // 这行代码将 udphdr 转换为 char * 类型的指针，并偏移 length 字节，然后将该位置的值设置为空字符 '\0'。这通常用于标记UDP数据报的结束。
                *((char *) udphdr + length) = '\0';

                uint16_t upd_payload_len = length - sizeof(struct rte_udp_hdr);


                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                printf("接收方 src: %s:%d--->", inet_ntoa(addr), ntohs(udphdr->src_port));

                addr.s_addr = iphdr->dst_addr;
                printf("dst: %s:%d, upd_payload_len=%d,upd_payload_data=%s\n", inet_ntoa(addr), ntohs(udphdr->dst_port),
                       upd_payload_len, (char *) (udphdr + 1));

#if ENABLE_SEND
                struct rte_mbuf *txmbuf = ng_send_udp(mbuf_pool, (uint8_t *) (udphdr + 1), length);
                rte_eth_tx_burst(gDpdkPortId, 0, &txmbuf, 1);
                rte_pktmbuf_free(txmbuf);
#endif
                rte_pktmbuf_free(mbufs[i]);
            }

#if ENABLE_ICMP
            if (iphdr->next_proto_id == IPPROTO_ICMP) {
                struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *) (iphdr + 1);
                // 调试信息
                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                printf("icmp ---> src: %s ", inet_ntoa(addr));

                if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) { // imcp ping 才回复
                    // 调试信息
                    addr.s_addr = iphdr->dst_addr;
                    printf(" local: %s , type : %d\n", inet_ntoa(addr), icmphdr->icmp_type);

                    struct rte_mbuf *txmbuf = ng_send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes,
                                                           iphdr->dst_addr, iphdr->src_addr,
                                                           icmphdr->icmp_ident, icmphdr->icmp_seq_nb);
                    rte_eth_tx_burst(gDpdkPortId, 0, &txmbuf, 1);
                    rte_pktmbuf_free(txmbuf);
                    rte_pktmbuf_free(mbufs[i]);
                }
            }
#endif
        }
#if ENABLE_TIMER
        // prev_tsc=之前  cur_tsc=当前 diff_tsc=差值
        static uint64_t prev_tsc = 0, cur_tsc;
        uint64_t diff_tsc;
        // 用于获取处理器的时间戳计数器(TSC,Time Stamp Counter)的值。TSC是一个高精度的计时器，
        // 由CPU的内部寄存器维护,它记录了自处理器上电以来的时钟周期数
        // 提供了纳秒级精度的时间测量，非常适合用于测量短时间间隔（例如性能测试、延迟测量等)
        // 在网络数据包处理等高性能计算场景中，可以使用 TSC 进行详细的性能分析和优化
        cur_tsc = rte_rdtsc();
        // 打印测试
        // printf("cur_tsc = %lul\n", cur_tsc);
        diff_tsc = cur_tsc - prev_tsc; // 当前时间 减去 之前的一次 得到一个差
        if (diff_tsc > TIMER_RESOLUTION_CYCLES) { // diff_tsc 差值 大于 表示达到的触发时间
            // 获取 TSC 频率
            uint64_t tsc_hz = rte_get_tsc_hz();
            // 换算成秒
            double diff_seconds = (double) diff_tsc / tsc_hz;
            // 打印差值的秒数
            printf("diff_tsc= %lu diff_seconds= %f seconds\n", diff_tsc, diff_seconds);

            rte_timer_manage();
            prev_tsc = cur_tsc;
        }
#endif

    }

}


