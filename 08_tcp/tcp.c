

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>

#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "arp.h"

#define ENABLE_SEND        1
#define ENABLE_ARP         1
#define ENABLE_ICMP        1
#define ENABLE_ARP_REPLY   1

#define ENABLE_DEBUG       1
#define ENABLE_TIMER       1
// ring buffer 开关
#define ENABLE_RINGBUFFER  1
// 多线程开关
#define ENABLE_MULTHREAD   1
// upd server 服务开关
#define ENABLE_UDP_APP     1
// tcp Server 服务开关
#define ENABLE_TCP_APP       1


#define NUM_MBUFS (4096-1)

#define BURST_SIZE    32
#define RING_SIZE     1024
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


#if ENABLE_RINGBUFFER
struct inout_ring {
    struct rte_ring *in;
    struct rte_ring *out;
};

struct inout_ring *rInst = NULL;

// 初始化 ring Buffer 单例
static struct inout_ring *ringInstance(void) {
    if (rInst == NULL) {
        rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
        memset(rInst, 0, sizeof(struct inout_ring)); // 初始化数据
    }
    return rInst;
}

#endif

#if ENABLE_UDP_APP

static int udp_process(struct rte_mbuf *udpmbuf);

static int udp_out(struct rte_mempool *mbuf_pool);

#endif


#if ENABLE_TCP_APP

static int ng_tcp_process(struct rte_mbuf *tcpmbuf);

static int ng_tcp_out(struct rte_mempool *mbuf_pool);

#endif

// 定义一个端口的id表示的是 绑定的网卡id
int gDpdkPortId = 0;


// 设置端口配置信息
static const struct rte_eth_conf port_conf_default = {
        .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

// 初始化获取网卡网口驱动信息
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


// 构造udp发送所需要的数据包结构化的内容
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

// 暂时没有使用到该函数 增加  __attribute__((unused)) 消除编译警告
static struct rte_mbuf *
ng_send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length) __attribute__((unused));
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

// 构造arp协议发送所需要的数据包结构化的内容
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
    // mempool --> mbuf 从内存池中获取一个mbuf ,使用内存池最小的单位是 mbuf
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "ng_send_arp rte_pktmbuf_alloc 分配内存失败\n");
    }
    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;
    // 从mbuf里面把对应的数据 请注意mbuf是一个结构体 这个结构体和具体存储的数据是分离的 需要拿到存储数据具体的位置
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


// 构造icmp协议发送所需要的数据包结构化的内容
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

    icmp->icmp_cksum = 0; // 先初始化 因为 ng_checksum函数 会用到icmp_cksum
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

// 打印mac地址字符串形式函数
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
    struct inout_ring *ring = ringInstance();
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
        // rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
        // rte_pktmbuf_free(arpbuf);
        // 把需要发送的数据入队到 ring Buffer(线程安全的)
        // 缓冲区中存储的是 arpbuf 指向的 rte_mbuf 的地址，而不是 arpbuf 变量本身。
        // arpbuf 变量被回收，rte_mbuf 结构体本身依然存在于内存中，消费者可以从环形缓冲区中正常取出并使用这个结构体。
        rte_ring_mp_enqueue_burst(ring->out, (void **) &arpbuf, 1, NULL);
    }
}

#endif

#if ENABLE_MULTHREAD

/**
 * 接收 ring->in buffer 取出网卡数据包队列线程
 * @param arg DPDK内存池对象
 * @return
 */
static int pkt_process(void *arg) {
    // 内存池对象转换
    struct rte_mempool *mbuf_pool = (struct rte_mempool *) arg;
    struct inout_ring *ring = ringInstance();

    while (1) {
        struct rte_mbuf *mbufs[BURST_SIZE];
        // 取数据 出队 支持多消费者安全 每次可以出队多个对象，最多 n 个对象。
        unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in, (void **) mbufs, BURST_SIZE, NULL);
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
                        // rte_eth_tx_burst(gDpdkPortId, 0, &arpmbuf, 1); 先屏蔽
                        // 把需要发送的数据入队到 ring Buffer(线程安全的)
                        rte_ring_mp_enqueue_burst(ring->out, (void **) &arpmbuf, 1, NULL);
                        // rte_pktmbuf_free(arpmbuf); 先屏蔽
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
                        rte_pktmbuf_free(mbufs[i]);
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
            // 获取ip头 转化为 结构体数据
            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *,
                                                                 sizeof(struct rte_ether_hdr));
            // 判断是否是udp协议
            if (iphdr->next_proto_id == IPPROTO_UDP) {
                // 处理udp协议数据
                udp_process(mbufs[i]);
            }

#if ENABLE_TCP_APP
            if (iphdr->next_proto_id == IPPROTO_TCP) {
                ng_tcp_process(mbufs[i]);
            }
#endif

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
                    // rte_eth_tx_burst(gDpdkPortId, 0, &txmbuf, 1);
                    // rte_pktmbuf_free(txmbuf);
                    // 把需要发送的数据入队到 ring Buffer(线程安全的)
                    rte_ring_mp_enqueue_burst(ring->out, (void **) &txmbuf, 1, NULL);

                    rte_pktmbuf_free(mbufs[i]);
                }
            }
#endif
        }
#if ENABLE_UDP_APP
        // 为什么不写在for循环里面???
        udp_out(mbuf_pool);
#endif
    }
    return 0;
}

#endif

#if ENABLE_UDP_APP

static struct localhost *lhost = NULL;

// connfd--> 对应底层就是 struct localhost
struct localhost {
    int fd;

    //unsigned int status; // 增加一个状态 表示阻塞和非阻塞??? 这里暂时就不实现了
    uint32_t localip; // ip --> mac
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint16_t localport;

    int protocol;
    struct rte_ring *sndbuf;
    struct rte_ring *rcvbuf;

    // 连接数超级多的时候不建议使用链表 推荐使用 红黑树
    struct localhost *prev; // 加入链表里面
    struct localhost *next; // 为了做多个链接
    // 增加一个条件变量
    pthread_cond_t cond;
    pthread_mutex_t mutex;

};


#define DEFAULT_FD_NUM    3

static int get_fd_frombitmap(void) {
    int fd = DEFAULT_FD_NUM; // 先写死
    return fd;
}

/**
 * 通过pf查找是那个会话
 * @param sockfd
 * @return
 */
static struct localhost *get_hostinfo_fromfd(int sockfd) {
    struct localhost *host;
    for (host = lhost; host != NULL; host = host->next) {
        if (sockfd == host->fd) {
            return host;
        }
    }
    return NULL;
}

/**
 * 查找 host
 * @param dip
 * @param port
 * @param proto
 * @return
 */
static struct localhost *get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto) {
    struct localhost *host;
    for (host = lhost; host != NULL; host = host->next) {
        if (dip == host->localip && port == host->localport && proto == host->protocol) {
            return host;
        }
    }
    return NULL;
}


// arp
struct offload {
    // 为什么没有定义mac地址 因为可以从arp中获取
    // 一个udp数据包  包含 哪些数据
    uint32_t sip;
    uint32_t dip;

    uint16_t sport;
    uint16_t dport;

    int protocol;
    // 数据
    unsigned char *data;
    // 数据长度
    uint16_t length;

};

/**
 * 处理 UDP server 线程
 * @param udpmbuf
 * @return
 */
static int udp_process(struct rte_mbuf *udpmbuf) {
    /**
     * push到 recv buffer
     * 1、解析数据
     * 2、填充offload
     * 3、push到 recv buffer
     */
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    // struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *) (iphdr + 1);
    // struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *) ((char *) iphdr + sizeof(struct rte_ipv4_hdr));
    // 上面注释两行写法不一样 功能一样
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *) (iphdr + 1);
    // if (ntohs (udphdr->src_port) != 8888) { // 做测试用的 可以后期删除
    //     continue;
    // }
    // 打印测试 打印ip地址
    struct in_addr addr;
    addr.s_addr = iphdr->src_addr;
    printf("udp_process ---> src: %s:%d \n", inet_ntoa(addr), ntohs(udphdr->src_port));
    // 查找信息
    struct localhost *host = get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
    if (host == NULL) { // 应该是正常的 有一些 可能是广播的数据  对应的host可能不存在 (此情况不做处理退出即可)
        rte_pktmbuf_free(udpmbuf);
        return -3;
    }
    // 构造 offload 数据
    struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL) { // return 需要清空mbuf
        rte_pktmbuf_free(udpmbuf);
        return -1;
    }
    // ip 和 端口 进行赋值
    ol->dip = iphdr->dst_addr;
    ol->sip = iphdr->src_addr;
    ol->sport = udphdr->src_port;
    ol->dport = udphdr->dst_port;

    ol->protocol = IPPROTO_UDP;
    ol->length = ntohs(udphdr->dgram_len); // todo 是否应该减掉首部长度 - sizeof(struct rte_udp_hdr);
    // 分配内存
    ol->data = rte_malloc("unsigned char*", ol->length - sizeof(struct rte_udp_hdr), 0);
    if (ol->data == NULL) { // 分配失败 释放内存
        rte_pktmbuf_free(udpmbuf);
        rte_free(ol);
        return -2;
    }
    // 拷贝内容 udphdr(头部大小) + 1 表示 移动到 upd_payload_data首地址进行复制
    rte_memcpy(ol->data, (unsigned char *) (udphdr + 1), ol->length - sizeof(struct rte_udp_hdr));
    // 之前没有把 udp header 头长度减去有问题
    // 修改数据长度 减去udphdr的大小
    ol->length = ol->length - sizeof(struct rte_udp_hdr);
    // 网络字节顺什么时候转换 两个字节以上包含两个字节
    uint16_t length = ntohs(udphdr->dgram_len);
    // 这行代码将 udphdr 转换为 char * 类型的指针，并偏移 length 字节，然后将该位置的值设置为空字符 '\0'。这通常用于标记UDP数据报的结束。
    // *((char *) udphdr + length) = '\0'; 此行存在问题

    // 不修改原始数据 创建临时打印测试
    uint16_t upd_payload_len = length - sizeof(struct rte_udp_hdr);
    char temp_buffer[upd_payload_len + 1]; // +1是为了存储终止符
    char *payload = (char *) (udphdr + 1);
    memcpy(temp_buffer, payload, upd_payload_len);
    temp_buffer[upd_payload_len] = '\0'; // 在复制的缓冲区中添加终止符 然后打印该变量


    addr.s_addr = iphdr->dst_addr;
    printf("dst: %s:%d, upd_payload_len=%d,upd_payload_data=%s\n", inet_ntoa(addr), ntohs(udphdr->dst_port),
           upd_payload_len, (char *) (udphdr + 1));
    // 生产者-> 某个对象的指针 插入到环形队列中。线程安全的
    rte_ring_mp_enqueue(host->rcvbuf, ol); // push 到 recv buffer
    // 通知其他线程 数据已经准备好
    pthread_mutex_lock(&host->mutex);
    pthread_cond_signal(&host->cond);
    pthread_mutex_unlock(&host->mutex);

    // enqueue --> recvbuff
    rte_pktmbuf_free(udpmbuf);
    return 0;
}

static int ng_encode_udp_apppkt(
        uint8_t *msg, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
        unsigned char *data, uint16_t total_len) {

    // dpdp从最开始就创建了一个内存池
    // encode 打包成udp的包
    // 1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *) msg;
    rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);

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
    ip->src_addr = sip;
    ip->dst_addr = dip;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    // 3 udphdr 偏移
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *) (msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = sport;
    udp->dst_port = dport;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);
    // 从  (udp + 1) 位置 复制udplen个字节
    rte_memcpy((uint8_t *) (udp + 1), data, udplen);
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp); // l4表示第四层

    // 打印测试
    struct in_addr addr;
    addr.s_addr = sip;
    addr.s_addr = dip;
    char src_mac_str[RTE_ETHER_ADDR_FMT_SIZE];
    char dst_mac_str[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(src_mac_str, RTE_ETHER_ADDR_FMT_SIZE, &eth->s_addr);
    rte_ether_format_addr(dst_mac_str, RTE_ETHER_ADDR_FMT_SIZE, &eth->d_addr);

    // ntohs 表示将16位的 网络字节序 转换 为主机字节序(人类可阅读的模式)
    printf("发送方 --> src: %s:%s:%d", src_mac_str, inet_ntoa(addr), ntohs(udp->src_port));
    printf("-->dst: %s:%s:%d\n", dst_mac_str, inet_ntoa(addr), ntohs(udp->dst_port));
    return 0;
}

static struct rte_mbuf *ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
                                   uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
                                   uint8_t *data, uint16_t length) {
    // mempool --> mbuf 从内存池中获取一个mbuf ,使用内存池最小的单位是 mbuf
    // 从 内存池一次性拿多少数据出来
    // 14(以太网头大小) + 20(IPV4头大小) + 8(UDP头大小) + (剩余应用层数据大小.....)
    // 42(以太网头大小+IPV4头大小+UDP头大小)
    // 此时该 length 是 udp_payload_len 有效负载长度
    const unsigned total_len = 42 + length;
    // todo 这里 -8 去掉 就可以正常回显数据了 但是 06_netarch 就不需要 还需要排查为什么
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t * pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ng_encode_udp_apppkt(pktdata, sip, dip, sport, dport, srcmac, dstmac, data, total_len);
    return mbuf;
}


// offload 转 mbuf
// mempool --> mbuf 从内存池中获取一个mbuf ,使用mempool内存池最小的单位是 mbuf
static int udp_out(struct rte_mempool *mbuf_pool) {
    struct localhost *host;
    // 需要遍历所有的host 取出 send buf 需要发送的数据
    for (host = lhost; host != NULL; host = host->next) {
        struct offload *ol;
        // consumer 多线程消费者安全模式下 从环形队列中出队单个对象
        int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **) &ol);
        // rte_ring_mc_dequeue_bulk rte_ring_mc_dequeue_burst
        if (nb_snd < 0) {
            continue;
        }
        // 调试信息
        struct in_addr addr;
        addr.s_addr = ol->dip;
        printf("udp_out ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));

        uint8_t * dstmac = ng_get_dst_macaddr(ol->dip);
        if (dstmac == NULL) { // 没有的话 需要发一次arp数据包过去
            struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, ol->sip, ol->dip);

            struct inout_ring *ring = ringInstance();
            // 把需要发送的数据入队到 ring Buffer(线程安全的)
            rte_ring_mp_enqueue_burst(ring->out, (void **) &arpbuf, 1, NULL);
            // 在次写回到sndbuf中？ 没明白此举含义
            rte_ring_mp_enqueue(host->sndbuf, ol);
        } else {
            struct rte_mbuf *udpbuf = ng_udp_pkt(
                    mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport, host->localmac, dstmac, ol->data, ol->length);

            struct inout_ring *ring = ringInstance();
            // 把需要发送的数据入队到 ring Buffer(线程安全的)
            rte_ring_mp_enqueue_burst(ring->out, (void **) &udpbuf, 1, NULL);
        }
    }
    return 0;
}

/**
 * hook 钩子函数  socket 和系统函数冲突 修改名字为 nsocket
 * @param domain
 * @param type
 * @param protocol
 * @return
 */
static int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused)) int protocol) {
    // bit map
    int fd = get_fd_frombitmap(); //分配一个可用的fd
    // struct localhost *host = (struct localhost *) malloc(sizeof(struct localhost));
    struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
    if (host == NULL) { //创建失败
        return -1;
    }
    // 初始化 host 值 为 0
    memset(host, 0, sizeof(struct localhost));
    host->fd = fd;
    if (type == SOCK_DGRAM) {
        host->protocol = IPPROTO_UDP;
    }
    // Makefile
    // else if (type == SOCK_STREAM) {
    //     host->protocol = IPPROTO_TCP;
    // }
    // 创建 ring buffer
    host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (host->rcvbuf == NULL) {
        rte_free(host);
        return -1;
    }
    // 创建 ring buffer
    host->sndbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (host->sndbuf == NULL) {
        rte_ring_free(host->rcvbuf);
        rte_free(host);
        return -1;
    }
    // 初始化 条件变量
    // 这里不是很明白 在这里初始化 当前函数如果执行完 这两个变量 不会回收吗？？
    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));
    // 初始化 条件变量
    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    // 将新创建的host添加到链表中
    LL_ADD(host, lhost);
    return fd;
}


static int nbind(int sockfd, const struct sockaddr *addr, __attribute__((unused)) socklen_t addr_len) {
    struct localhost *host = get_hostinfo_fromfd(sockfd);
    if (host == NULL) {
        return -1;
    }
    const struct sockaddr_in *laddr = (const struct sockaddr_in *) addr;

    host->localport = laddr->sin_port;
    // host->localip = laddr->sin_addr.s_addr;
    rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);
    return 0;
}

static ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags,
                         struct sockaddr *src_addr, __attribute__((unused)) socklen_t *addr_len) {
    struct localhost *host = get_hostinfo_fromfd(sockfd);
    if (host == NULL) {
        return -1;
    }
    /**
     * sockfd 分为阻塞和非阻塞
     */
    struct offload *ol = NULL;
    unsigned char *ptr = NULL;

    struct sockaddr_in *saddr = (struct sockaddr_in *) src_addr;
    // 如果非阻塞
    int nb = -1;
    // nb = rte_ring_mc_dequeue(host->rcvbuf, (void **) &ol);
    // if (nb < 0) {
    //     return -1;
    // }
    // 消费者 线程安全的
    // 在这里我们实现一个阻塞的
    pthread_mutex_lock(&host->mutex);
    // 如果一直没有数据阻塞在这里 如果有数据就往下面走
    while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **) &ol)) < 0) {
        pthread_cond_wait(&host->cond, &host->mutex);
    }
    pthread_mutex_unlock(&host->mutex);
    //
    saddr->sin_port = ol->sport;
    rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));
    if (len < ol->length) { // 当 buf len 小于 实际 upd_payload_len 说明 数据包 大于 缓存buf
        // 重新把这个节点再放到 recv buffer 里面
        rte_memcpy(buf, ol->data, len);
        // 开辟内存并且赋值数据
        ptr = rte_malloc("unsigned char *", ol->length - len, 0);
        rte_memcpy(ptr, ol->data + len, ol->length - len);

        ol->length -= len;
        // 释放原来的重新赋值
        rte_free(ol->data);
        ol->data = ptr;

        // 这一步是因为 udp_recv_buffer 设置了固定长度 需要反复进行读取数据
        rte_ring_mp_enqueue(host->rcvbuf, ol);

        return len;
    } else {
        rte_memcpy(buf, ol->data, ol->length); // todo 可能有问题 目前 length 包含 udp header
        // 释放内存
        ssize_t length = ol->length;
        rte_free(ol->data);
        rte_free(ol);
        // return ol->length; // 不能直接返回 因为前面释放了这个内存，rte_free之后对 ol->length 的访问就会变得不可预测
        return length;
    }
}

static ssize_t
nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags,
        const struct sockaddr *dest_addr, __attribute__((unused)) socklen_t addr_len) {
    /**
     * 这个地方 没必要和recvfrom一样 加 pthread_cond_wait 条件等待 很容易发生死锁
     * 三个线程 2组 ring buffer
     */
    struct localhost *host = get_hostinfo_fromfd(sockfd);
    if (host == NULL) {
        return -1;
    }

    const struct sockaddr_in *daddr = (const struct sockaddr_in *) dest_addr;

    struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL) {
        return -1;
    }

    ol->dip = daddr->sin_addr.s_addr;
    ol->dport = daddr->sin_port;
    ol->sip = host->localip;
    ol->sport = host->localport;
    ol->length = len;
    // 打印测试
    struct in_addr addr;
    addr.s_addr = ol->dip;
    printf("nsendto ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));

    // 开辟内存
    ol->data = rte_malloc("unsigned char *", len, 0);
    if (ol->data == NULL) { // 如果失败
        rte_free(ol);
        return -1;
    }
    // 赋值数据
    rte_memcpy(ol->data, buf, len);
    // 入队到 发送队列中
    rte_ring_mp_enqueue(host->sndbuf, ol);

    return len;
}


static int nclose(int sockfd) {
    struct localhost *host = get_hostinfo_fromfd(sockfd);

    if (host == NULL) {
        return -1;
    }
    LL_REMOVE(host, lhost);

    if (host->rcvbuf) {
        rte_ring_free(host->rcvbuf);
    }
    if (host->sndbuf) {
        rte_ring_free(host->sndbuf);
    }
    rte_free(host);
    return 0;
}


#define UDP_APP_RECV_BUFFER_SIZE    128

/**
 * 跑 udp server 把它跑通 在现在的一个协议栈上 socket bind recvfrom sendto close 要自己实现 内核这五个函数(五个接口)
 * 1、udp server在做的时候也是一个线程
 * @param arg
 * @return
 */
static int udp_server_entry(__attribute__((unused))  void *arg) {
    // connfd 生命周期 socket分配一个 fd 唯一值 对应(local_ip local_port)
    int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
    if (connfd == -1) {
        printf("sockfd failed\n");
        return -1;
    }
    struct sockaddr_in localaddr, clientaddr; // struct sockaddr
    memset(&localaddr, 0, sizeof(struct sockaddr_in));

    localaddr.sin_port = htons(8889);
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = inet_addr("192.168.79.201"); // todo 0.0.0.0
    int bind_id = nbind(connfd, (struct sockaddr *) &localaddr, sizeof(localaddr));

    if (bind_id == -1) {
        perror("bind failed");
        close(connfd);
        return -1;
    }
    printf("Bind successful on %s:%d\n", inet_ntoa(localaddr.sin_addr), ntohs(localaddr.sin_port));


    char buffer[UDP_APP_RECV_BUFFER_SIZE] = {0};
    socklen_t addrlen = sizeof(clientaddr);
    while (1) {
        if (nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0,
                      (struct sockaddr *) &clientaddr, &addrlen) < 0) {
            continue;
        } else {
            printf("recv from %s:%d, data:%s\n", inet_ntoa(clientaddr.sin_addr),
                   ntohs(clientaddr.sin_port), buffer);
            nsendto(connfd, buffer, strlen(buffer), 0,
                    (struct sockaddr *) &clientaddr, sizeof(clientaddr));
        }
    }
    nclose(connfd);
    return 0;
}

#endif


#if ENABLE_TCP_APP

static int ng_tcp_process(struct rte_mbuf *tcpmbuf) {
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(tcpmbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *) (iphdr + 1);

    // checksum校验值处理
    uint16_t tcp_cksum = tcphdr->cksum;
    tcphdr->cksum = 0; // 初始化数据

    uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);

#if 1
    if (cksum != tcp_cksum) { // cksum 程序进行校验值 tcp_cksum 发送过来的数据包值
        printf("cksum: %x, tcp cksum: %x\\n", cksum, tcp_cksum);
        return -1;
    }
#endif


    return 0;
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

#if ENABLE_MULTHREAD
    struct inout_ring *ring = ringInstance();
    if (ring == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create ring\n");
    }
    // 在内存中间分配两个ring
    // RING_F_SP_ENQ 单生产者入队的标志、使用这个标志意味着在环形缓冲区中只有一个生产者线程会进行入队操作
    // RING_F_SC_DEQ 单消费者出队的标志。使用这个标志意味着在环形缓冲区中只有一个消费者线程会进行出队操作
    // RING_F_SP_ENQ|RING_F_SC_DEQ 这两个标志一起使用，表示该环形缓冲区是单生产者、单消费者模型。这种模型下，环形缓冲区的入队和出队操作都不需要使用锁，从而提高了性能。
    if (ring->in == NULL) {
        ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }
    // 在内存中间分配一个ring
    if (ring->out == NULL) {
        ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }
    // enqueue 系列(入队插入操作)

    // rte_ring_mp_enqueue()
    // rte_ring_mp_enqueue_burst()
    // rte_ring_mp_enqueue_bulk()

    // rte_ring_sp_enqueue()
    // rte_ring_sp_enqueue_burst()
    // rte_ring_sp_enqueue_bulk()

    // rte_ring_enqueue()
    // rte_ring_enqueue_burst()
    // rte_ring_enqueue_bulk()

    // dequeue 系列(出队取出操作)

    // rte_ring_mc_dequeue()
    // rte_ring_mc_dequeue_burst()
    // rte_ring_mc_dequeue_bulk()

    // rte_ring_sc_dequeue()
    // rte_ring_sc_dequeue_burst()
    // rte_ring_sc_dequeue_bulk()

    // rte_ring_dequeue()
    // rte_ring_dequeue_burst()
    // rte_ring_dequeue_bulk()

    // 三个入队 三个出队
    // 多个地方入队 多线程的话使用 rte_ring_mp_enqueue_burst()
    // 不是线程安全的 如果只有一个地方入队可以使用这个 rte_ring_sp_enqueue_burst()
    // 出队
    // enqueue --> in ring
#endif
#if ENABLE_MULTHREAD
    // 启动多线程 暂时开一个线程 处理数据包 跟cpu绑定的 一一对应的
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(pkt_process, mbuf_pool, lcore_id);
#endif

#if ENABLE_UDP_APP
    // udp server 暂时开一个线程 处理数据包 跟cpu绑定的 一一对应的
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(udp_server_entry, mbuf_pool, lcore_id);
#endif

    while (1) {
        // rx
        // 接受数据的时候 包的数据量最大可以写入128个
        // 如果超过128 可能会出错 机器网卡可能会重启 、丢弃还是重启 还不太确定 ，超出了机器可能会重启 或者宕机 具体要看什么情况
        struct rte_mbuf *rx[BURST_SIZE]; // 也可以设置大一点128个
        // 通过该方法接受网卡数据
        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, rx, BURST_SIZE);
        if (num_recvd > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        } else if (num_recvd > 0) { // 如果大于0 直接就入队了
            // Single Producer 该函数适用于只有一个生产者进行入队操作的场景
            rte_ring_sp_enqueue_burst(ring->in, (void **) rx, num_recvd, NULL);
            // rte_ring_mp_enqueue_burst  multi-producers 将多个对象批量入队到环形队列中
        }
        // tx
        struct rte_mbuf *tx[BURST_SIZE];
        // 批量方式出队的函数
        // 适用于单消费者模式 即环形缓冲区中只有一个线程会进行出队操作。使用单消费者模式可以避免使用锁，从而提高性能
        unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void **) tx, BURST_SIZE, NULL);
        if (nb_tx > 0) {
            // 发送数据到网卡
            rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);

            unsigned i = 0;
            for (i = 0; i < nb_tx; i++) {
                rte_pktmbuf_free(tx[i]); // 释放
            }
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


