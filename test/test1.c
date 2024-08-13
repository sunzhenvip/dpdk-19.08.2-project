#include <stdio.h>
#include <stdlib.h>


#include <stdio.h>
#include <arpa/inet.h>


struct test {
    int value;
};
//

 int (* ( *  (*pfunc)(int *)   )[5]   )       (int *)  ;

// 指针数组 每个元素存的是一个函数指针

int (*ff)[55]; // 二

// 现吊事
int inner_function(int *p) {
    return *p + 1;
}
typedef int (*inner_function_type)(int *);

// 全局数组，用来保存函数指针
inner_function_type functions_array[5];


// 外部函数，返回函数指针数组的指针
inner_function_type ( *outer_function(int *p) )[5] {
    for (int i = 0; i < 5; i++) {
        functions_array[i] = inner_function;
    }
    return &functions_array;
}

// 初始化 test 结构体数组
void init_test(struct test **tests, int size) {
    printf(" init_test = %p\n", tests + 2);
    for (int i = 0; i < size; i++) {
        *(tests + i) = malloc(sizeof(struct test));
        // tests[i] = malloc(sizeof(struct test));  // 分配内存
        if (tests[i] == NULL) {
            perror("Failed to allocate memory");
            exit(EXIT_FAILURE);
        }
        tests[i]->value = i;  // 初始化 value
    }
}

// 修改 test 结构体数组
void modify_test(struct test **tests, int size) {
    for (int i = 0; i < size; i++) {
        tests[i]->value = tests[i]->value * 10;  // 修改 value
    }
}


int (*func1())[10] {
    static int data[10];
    // 初始化数组
    for (int i = 0; i < 10; ++i) {
        data[i] = i;
    }
    // 返回指向数组的指针
    return &data;
}


#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 79, 201); // dpdk端口设置的IP

int main() {
    int i = 0;
    for (i = 0; i < 254; i++) {
        uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));
        struct in_addr addr;
        addr.s_addr = dstip;
        printf("arp_request_timer_cb arp ---> src: %s \n", inet_ntoa(addr));


    }
    return 0;

    struct bs{
        unsigned m;
        unsigned n: 4;
        unsigned char ch: 6;
    } abc123 = { 0xad, 0xE, '$'};
    //第一次输出
    printf("%#x, %#x, %c\n", abc123.m, abc123.n, abc123.ch);
    //更改值后再次输出
    abc123.m = 0xb8901c;
    abc123.n = 0x2d;
    abc123.ch = 'z';
    printf("%#x, %#x, %c\n", abc123.m, abc123.n, abc123.ch);


    int (*array123)[10] = func1();
    // int (* (*  (*pfunc)(int *)   )   [5])       (int *)  ;
    int (* (*(*pfunc)(int *)) [5]) (int *);

    pfunc = outer_function;

    // 调用 pfunc
    int arg = 10;
    int (* (*funcs)[5])(int *) = pfunc(&arg);
    for (int i = 0; i < 5; i++) {
        int result = (*funcs)[i](&arg);
        printf("Result of function %d: %d\n", i, result);
    }


    int a123[3][4] = { {0, 1, 2, 3}, {4, 5, 6, 7}, {8, 9, 10, 11} };
    int (*p123)[4] = a123;  // *p123 表示指针 指向一个数组[4]类型


    int *p1234 = *(p123+1) +1;

    printf("%d\n", sizeof((p123)));



    char abc[3][4] = {{0, 1, 2,  3},
                     {4, 5, 6,  7},
                     {8, 9, 10, 11}};


    char **bacff = &abc[0][0];

    char *ff1 =  abc + 1;
    char (*pabc)[4] = abc + 2;
    printf("%d\n", sizeof(*(pabc + 1)));

    int arr10[3][3] = {{1, 2, 3},
                       {4, 5, 6},
                       {7, 8, 9}};


    int *ptr = &arr10[0][0];
    for (int i = 0; i < 9; i++) {
        printf("%d ", *(ptr + i));
        if ((i + 1) % 3 == 0) {
            printf("\n");
        }
    }


    int a = 16, b = 932, c = 100;


    //定义一个指针数组
    int *(arr[3]) = {&a, &b, &c};//也可以不指定长度，直接写作 int *arr[]

    int *arr2[] = {&a, &b, &c};

    // 意思是说 每一个 test1[i] 指向一个指针类型的test
    //  每一个元素是一个 struct test 指针类型数据
    struct test *test1[2];
    printf(" struct test *test1[2] = %p\n", test1);
    // 初始化 test1
    init_test(test1, 2);

    // 打印初始化后的值
    for (int i = 0; i < 2; i++) {
        printf("test1[%d]->value = %d\n", i, test1[i]->value);
    }

    // 修改 test1
    modify_test(test1, 2);

    // 打印修改后的值
    for (int i = 0; i < 2; i++) {
        printf("test1[%d]->value = %d\n", i, test1[i]->value);
    }

    // 释放内存
    for (int i = 0; i < 2; i++) {
        free(test1[i]);
        test1[i] = NULL;
    }

    int *ff = malloc(sizeof(int));
    *ff = 8;
    // 数组方式访问
    printf("ff = %d\n", ff[0]);

    // dataType *arrayName[length];
    // 指针数组定义规范  dataType *arrayName[length] 其中 []优先级高于*   可以理解为 dataType **arrayName 或者 dataType *(arrayName[length])
    return 0;
}

// C语言标准规定，对于一个符号的定义，编译器总是从它的名字开始读取，然后按照优先级顺序依次解析。对，从名字开始，不是从开头也不是从末尾，这是理解复杂指针的关键！

// C语言标准规定, 对于一个符号的定义,编译器总是从她的名字开始读取,然后按照优先级顺序一次解析.对 从名字开始 ,而不是从开头也不是从末尾,这是理解复杂指针的关键!说的对吗
