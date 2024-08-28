

netarch.c文件中 MAKE_IPV4_ADDR 方法修改成自己的实际IP地址

编译测试程序 gcc -o unix_udp unix_udp.c
运行  ./unix_udp
   Bind successful on 0.0.0.0:8889
   recv from 192.168.79.9:8888, data:http://www.cmsoft.cn QQ:10865600

已实现功能
    1、当前只支持绑定一个端口网卡
    2、arp 请求和响应功能
    3、icmp ping 功能
    4、udp接收与发送简易版已经实现
    5、接收和发送数据分离 使用 ring buffer 优化实现
    6、支持多线程

测试方法
    1、make 编译
    2、请修改 MAKE_IPV4_ADDR 对应的 IP地址 部署项目绑定的网口的 同网段IP地址
    3、udp_server_entry 方法中对应的函数也进行修改对应的IP
    2、请使用 NetAssist.exe 软件进行测试
    4、为了arp 更新 先执行 udp 在执行tcp (这一步 不确定是否需要)
    5、tcp 实现三次握手


1.不用offload，用rte mbufs来实现，udp 接口 如何实现？
2.sockfd如何做非阻塞。 如何实现？

tcp posix  api

滑动窗口 慢启动