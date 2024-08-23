#include <stdio.h>
#include <wchar.h>
#include <malloc.h>
#include <string.h>

#define PRINT_ARRAY(format, array, length) \
{ int array_index; \
for (array_index = 0; array_index < length; ++array_index) { \
  printf(format, array[array_index]); \
};\
printf("\n"); }

#define PRINT_INT_ARRAY(array, length) PRINT_ARRAY("%d, ", array, length)


#define  upd_payload_len  5
#define  UDP_APP_RECV_BUFFER_SIZE  128


// 编译 gcc -o test3 test3.c
// 运行 ./test3

int main() {

    char buf[UDP_APP_RECV_BUFFER_SIZE] = {0};

    unsigned char *data;
    data = (unsigned char *) malloc(sizeof(unsigned char) * upd_payload_len);
    memset(data, 0, upd_payload_len);
    for (int i = 0; i < upd_payload_len; ++i) {
        data[i] = i + 1;
    }

    // 测试边界问题
    PRINT_INT_ARRAY(data, 100);

    // ol->data, (unsigned char *) (udphdr + 1), ol->length - sizeof(struct rte_udp_hdr)
    memcpy(buf, data, upd_payload_len);


    printf("buf len = %lu\n", strlen(buf));

    return 0;

}
