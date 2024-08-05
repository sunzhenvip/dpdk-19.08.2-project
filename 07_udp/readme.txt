

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
11122