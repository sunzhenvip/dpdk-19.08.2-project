
#include <stdio.h>
#include <wchar.h>

#define PRINT_ARRAY(format, array, length) \
{ int array_index; \
for (array_index = 0; array_index < length; ++array_index) { \
  printf(format, array[array_index]); \
};\
printf("\n"); }

#define PRINT_INT_ARRAY(array, length) PRINT_ARRAY("%d, ", array, length)

// 大端和小端的概念
// 大多数x86系统都是小端  此系统为 为小端
// unsigned int ff = 0x12345678;
// 内存地址从低到高的存储顺序：
// 地址:   0x00  0x01  0x02  0x03
// 数据:   0x78  0x56  0x34  0x12
// 从 最低有效字节(指的是数值的最后面部分) 到 最高有效字节(指的是数值的最开始的部分) 的顺序存储
// 值是 0x12345678存储  大端模式和小端模式主要是针对多字节数据类型的字节顺序问题。
// 大端模式（Big-Endian）：是指多字节数据类型的高字节存储在低地址处，低字节存储在高地址处。
// 小端模式（Little-Endian）：是指多字节数据类型的低字节存储在低地址处，高字节存储在高地址处。
// 吃透大端和小端
// 大端和小端详解
int main() {

    // char a[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};

    // short int a = 230;     // 二进制数 00000101 表示十进制数 5
    // short int *f = &a;
    // printf("%p\n", f);
    // char *f = a;
    // printf("%p\n", f);
    // printf("%p\n", f+1);
    // printf("%d\n", *f);

    // int slice[4] = {0x78, 0x56, 0x34, 0x12};
    // //
    // PRINT_INT_ARRAY(slice, 4);
    // 大端 从小到大  小端 从大到小
    // 最低有效字节存储在低地址处，最高有效字节存储在高地址处。

    // unsigned int ff = 0x12345678;
    unsigned int ff = 0x0a0b0c0d;
    printf("%d\n", ff);

    unsigned int x = 0x12345678;
    unsigned char *c = (unsigned char *) &x;

    printf("Byte 0: %p\n", &c[0]); // 0x78 = 120
    printf("Byte 1: %p\n", &c[1]); // 0x56 = 86
    printf("Byte 2: %p\n", &c[2]); // 0x34 = 52
    printf("Byte 3: %p\n", &c[3]); // 0x12 = 18


    unsigned int j = 0x12345678; // 定义一个 32 位整数
    unsigned char *q = (unsigned char *) &j; // 将整数的地址强制转换为字节指针

    // 按照内存地址从低到高的顺序打印每个字节的值
    printf("Byte 0: %x\n", q[0]); // 打印第一个字节，内存地址最低，值为 0x12
    printf("Byte 1: %x\n", q[1]); // 打印第二个字节，值为 0x34
    printf("Byte 2: %x\n", q[2]); // 打印第三个字节，值为 0x56
    printf("Byte 3: %x\n", q[3]); // 打印第四个字节，内存地址最高，值为 0x78


    unsigned char slice[4] = {0x78, 0x56, 0x34, 0x12};
    PRINT_INT_ARRAY(slice, 4);

    int f = 0b1000000000010010;
    printf("%d\n", f);

    char *str2 = "C语言中文网";

    puts(str2);


    int arrayName[2][3];

    printf("%p\n", arrayName);

    return 0;
}
//

/**
1、最高有效字节最前面的数
2、最低有效字节是最后面数
*/


// short a = -18; 此时 a 的原码就是1000 0000 0001 0010
/**
short a ;6 = 0000 0000 0000 0110
18 = 10010

-18元码 = 1000 0000 0001 0010
a 的值a = -18;，此时 a 的原码就是1000 0000 0001 0010

*/

//  1111 1111 1110 1101
//  1111 1111 1110 1101 + 1 = 1111 1111 1110 1110


// 十进制 18 如何转换成二进制的 计算方法是啥