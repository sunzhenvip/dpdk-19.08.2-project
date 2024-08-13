#include <stdio.h>
#include <wchar.h>

#define PRINT_ARRAY(format, array, length) \
{ int array_index; \
for (array_index = 0; array_index < length; ++array_index) { \
  printf(format, array[array_index]); \
};\
printf("\n"); }

#define PRINT_INT_ARRAY(array, length) PRINT_ARRAY("%d, ", array, length)

#define N 100


int main() {
    char f1 = '\r';

    FILE *fp;
    char str[N + 1];
    //判断文件是否打开失败
    if ((fp = fopen("/data/network/clanguage/dpdk/dpdk-19.08.2-project/test/test.txt", "rt")) == NULL) {
        puts("Fail to open file!");
        return 0;
    }
    //循环读取文件的每一行数据
    while (fgets(str, N, fp) != NULL) {

        printf("%s", str);
    }

    //操作结束后关闭文件
    fclose(fp);
    return 0;

}
// 软件开发转行做fpga怎么样
