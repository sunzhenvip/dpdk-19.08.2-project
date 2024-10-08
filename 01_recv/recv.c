

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>

#define NUM_MBUFS (4096-1)

#define BURST_SIZE    32

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
    const int num_tx_queues = 0;
    struct rte_eth_conf port_conf = port_conf_default;
    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);


    if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 128,
                               rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool) < 0) {

        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");

    }
    // 还没确定怎么写
    // if (rte_eth_tx_queue_setup(
    //         gDpdkPortId, 0, 128, rte_eth_dev_socket_id(gDpdkPortId), &dev_info) < 0) {
    //     rte_exit(EXIT_FAILURE, "发送队列设置失败\n");
    // }

    if (rte_eth_dev_start(gDpdkPortId) < 0) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }


}



/**
 * 创建一个UDP的数据报文
 * 没有写完
 */
static void create_eth_ip_udp(uint8_t *msg, uint8_t *dst_mac, size_t total_len,
                              uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
    // eth ip udp
    // 创建以太网头部
    struct rte_ether_addr src_mac;
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *) msg;
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    // 获取绑定端口的mac地址
    rte_eth_macaddr_get(gDpdkPortId, &src_mac);
    rte_memcpy(eth->s_addr.addr_bytes, &src_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // ipv4-包头设置
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *) (eth + 1);
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    // 创建IP头部
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
                // 网络字节顺什么时候转换 两个字节以上包含两个字节
                uint16_t length = ntohs(udphdr->dgram_len);
                // 这行代码将 udphdr 转换为 char * 类型的指针，并偏移 length 字节，然后将该位置的值设置为空字符 '\0'。这通常用于标记UDP数据报的结束。
                *((char *) udphdr + length) = '\0';

                uint16_t upd_payload_len = length - sizeof(struct rte_udp_hdr);


                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                printf("src: %s:%d \n", inet_ntoa(addr), ntohs(udphdr->src_port));

                addr.s_addr = iphdr->dst_addr;
                printf("dst: %s:%d, upd_payload_len=%d,%s\n", inet_ntoa(addr), ntohs(udphdr->dst_port),
                       upd_payload_len, (char *) (udphdr + 1));

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


