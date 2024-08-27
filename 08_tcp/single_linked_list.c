

#include <stdio.h>
#include <arpa/inet.h>

#include <string.h>
#include <stdlib.h>


struct arp_entry {
    uint32_t age;
    struct arp_entry *next; // 下一个
    struct arp_entry *prev; // 上一个

};


// 缓存arp信息
struct arp_table {
    struct arp_entry *entries;
    int count;
};


static struct arp_table *arpt = NULL;


static struct arp_table *arp_table_instance(void) {

    if (arpt == NULL) {

        arpt = (struct arp_table *) malloc(sizeof(struct arp_table));
        if (arpt == NULL) {
            abort();
        }
        memset(arpt, 0, sizeof(struct arp_table));
    }
    return arpt;

}

static int set_arp_table(struct arp_entry *entry, struct arp_table *table) {
    entry->prev = ((void *) 0);
    entry->next = table->entries;
    if (table->entries != ((void *) 0)) {
        table->entries->prev = entry;
    }
    table->entries = entry;
}


int main() {
    // 测试链表
    // 初始化
    struct arp_table *table = arp_table_instance();


    for (int i = 1; i <= 2; i++) {
        struct arp_entry *entry = (struct arp_entry *) malloc(sizeof(struct arp_entry));
        // 初始化数据
        memset(entry, 0, sizeof(struct arp_entry));
        entry->age = i;
        set_arp_table(entry, table);
        table->count++;
    }

    struct arp_entry *iter;
    // 遍历输出
    for (iter = table->entries; iter != NULL; iter = iter->next) {
        printf("age = %d\n", iter->age);
    }


    printf(".............. end..................\n");
    return 0;
}