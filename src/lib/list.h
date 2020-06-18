#ifndef __LIST_H__
#define __LIST_H__

#include <stdint.h>
#include <stddef.h>

typedef struct node {
    void *data;
    struct node *next;
} node_t;

typedef struct list {
    node_t *head;
} list_t;

void list_init(list_t *);
void *list_pop(list_t *);
void list_push(list_t *, void *, size_t);
int list_head(list_t *);

#endif
