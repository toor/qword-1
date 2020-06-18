#include <stdint.h>
#include <stddef.h>
#include <lib/list.h>
#include <lib/cmem.h>

void list_init(list_t *l) {
    l->head = NULL;
}

void *list_pop(list_t *l) {
    node_t *head = l->head;

    if (head) {
        l->head = head->next;
        head->next = NULL;
    }

    return head->data;
}

void list_push(list_t *l, void *data, size_t len) {
    node_t *node = kalloc(sizeof(node_t));

    node->data = kalloc(len);
    node->next = l->head;

    memcpy(node->data, data, len);

    l->head = node;
}
