

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>

#define ENABLE_SEND        1
#define ENABLE_ARP        1


#define NUM_MBUFS (4096-1)

#define BURST_SIZE    32


#if ENABLE_SEND

static uint32_t gSrcIp; // 全局的一对一 如果多个这种写法就不行了
static uint32_t gDstIp;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

static uint16_t gSrcPort;
static uint16_t gDstPort;

#endif

int gDpdkPortId = 0;

static const struct rte_eth_conf port_conf_default = {
        .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

static void ng_init_port(struct rte_mempool *mbuf_pool) {

    uint16_t nb_sys_ports = rte_eth_dev_count_avail(); //
    if (nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info); //

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;
    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);


    // Invalid value for nb_tx_desc(=128), should be: <= 4096, >= 512, and a product of 1 调整为1024
    if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 1024,
                               rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool) < 0) {

        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");

    }
#if ENABLE_SEND
    // 接收多大 发送多大
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    // 第二个参数 对应的是那个队列 第三个参数对应的队列最大承载多少
    if (rte_eth_tx_queue_setup(
            gDpdkPortId, 0, 1024,
            rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
        rte_exit(EXIT_FAILURE, "发送队列设置失败\n");
    }
#endif

    if (rte_eth_dev_start(gDpdkPortId) < 0) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }


}


void print_mac(uint8_t *mac_addr);

void print_mac(uint8_t *mac_addr) {
    // 打印 MAC 地址，格式为 xx:xx:xx:xx:xx:xx
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4],
           mac_addr[5]);
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
static struct rte_mbuf *ng_send(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length) {
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

    // 初始化内存池
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
                                                            0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    ng_init_port(mbuf_pool);
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *) gSrcMac); // 原mac地址获取
    while (1) {

        struct rte_mbuf *mbufs[BURST_SIZE]; // 也可以设置大一点128个
        // 通过该方法接受网卡数据
        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
        if (num_recvd > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        }

        unsigned i = 0;
        for (i = 0; i < num_recvd; i++) {

            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
            if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }

            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *,
                                                                 sizeof(struct rte_ether_hdr));

            if (iphdr->next_proto_id == IPPROTO_UDP) {

                // struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *) (iphdr + 1);
                // 上一行代码修正版
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *) ((char *) iphdr + sizeof(struct rte_ipv4_hdr));
                if (ntohs (udphdr->src_port) != 8888) {
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
                struct rte_mbuf *txmbuf = ng_send(mbuf_pool, (uint8_t *) (udphdr + 1), length);
                rte_eth_tx_burst(gDpdkPortId, 0, &txmbuf, 1);
                rte_pktmbuf_free(txmbuf);
#endif
                rte_pktmbuf_free(mbufs[i]);
            }

        }

    }

}

// 下面是测试的代码
// 定义一个端口的id表示的是 绑定的网卡id
int gDpdkPortIdT = 0;
// 设置端口配置信息
static const struct rte_eth_conf port_conf_defaultT = {
        .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN} //
};

static void ng_init_portT(struct rte_mempool *mbuf_pool) {
    // 检测端口是否可用 dpdk 绑定了多少个网卡 这里应该是多少个
    uint16_t nb_sys_ports = rte_eth_dev_count_avail(); //
    if (nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "没有可用的网卡\n");
    }
    // 获取默认的第一个网口
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortIdT, &dev_info); // 第一个网口信息

    const int num_rx_queues = 1; // 接受 最多可以设置八个 因为有八个CPU当前机器
    const int num_tx_queues = 0; // 发送 暂时这个版本 不发送数据 先设置0
    // 多队列网卡的意思是 设置这个端口的配置信息
    // 用于配置以太网设备的全局参数。它通常在设置特定队列之前调用，用于初始化和配置设备的总体属性和行为
    rte_eth_dev_configure(gDpdkPortIdT, num_rx_queues, num_tx_queues, &port_conf_defaultT);
    // 用于配置和初始化特定 RX 队列的参数，包括 RX 描述符的数量、NUMA 节点和内存池。
    // 127 指的是可以堆积这么多 队列里面的数量是128
    int rte_eth_set_res = rte_eth_rx_queue_setup(gDpdkPortIdT, 0, 128,
                                                 rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool);
    // 如果设置失败不能启动
    if (rte_eth_set_res < 0) {
        rte_exit(EXIT_FAILURE, "设置接收队列失败\n");
    }
    // 设置完之后 启动接收队列
    if (rte_eth_dev_start(gDpdkPortIdT) < 0) {
        rte_exit(EXIT_FAILURE, "启动失败\n");
    }
}

// 增加原型不会有警告：‘test_main’先前没有原型 [-Wmissing-prototypes]
//  int test_main(int argc, char *argv[]) {
//      ^
// cc1: 警告：无法识别的命令行选项“-Wno-address-of-packed-member” [默认启用]
int test_main(int argc, char *argv[]);

int test_main(int argc, char *argv[]) {

    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "大页初始化失败");
    }
    // 初始化内存池 DPDK 一个进程确定一个内存池 内存会放在这个变量中
    // 设置4K 8K都是可以的 这里我们设置一个特殊的值 不去满足2的N次方 比如设置4096-1的好处  小于4k的放在4K里面 大于4K的 放在另外大于4K的地方

    // 初始化内存池
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
                                                            0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "内存池初始化失败");
    }
    // 初始化获取网卡驱动
    ng_init_portT(mbuf_pool);

    while (1) {
        // 接受数据的时候 包的数据量最大可以写入128个
        // 如果超过128 可能会出错 机器网卡可能会重启 、丢弃还是重启 还不太确定 ，超出了机器可能会重启 或者宕机 具体要看什么情况
        // rte_eth_rx_burst();
    }
}


