#include <stdlib.h>
#include "queue.h"

queue_t *queue_init()
{
    queue_t *q = (queue_t *) malloc(sizeof(queue_t));
    if (!q) {
        return NULL;
    }
    q->head = NULL;
    q->tail = NULL;
    q->size = 0;
    return q;
}

void queue_free(queue_t *q)
{
    /* First remove all elements */
    while (q->head) {
        queue_dequeue(q);
    }
    free(q);
}

int queue_enqueue(queue_t *q, void *d)
{
    queue_node_t *n = (queue_node_t *) malloc(sizeof(queue_node_t));
    if (!n) {
        return 1;
    }
    n->data = d;
    /* This element is the last one to be removed, so the next one is NULL */
    n->next = NULL;

    /* Is it the first element to be inserted? */
    if (!q->head) {
        q->head = n;
        q->tail = n;
    } else {
        /* Then n is the next of the previously last one */
        q->tail->next = n;
        /* And n is the new tail */
        q->tail = n;
    }
    q->size++;
    return 0;
}

void *queue_dequeue(queue_t *q)
{
    /* Case 1: the list is empty */
    if (!q->head) {
        return NULL;
    }
    queue_node_t *to_remove = q->head;
    void *to_return = to_remove->data;
    /* Case 2: only one element is left */
    if (q->head == q->tail) {
        q->head = NULL;
        q->tail = NULL;
    } else {
        /* Case 3: at least two elements left */
        q->head = q->head->next;
    }

    q->size--;
    /* Don't forget to free the node memory */
    free(to_remove);
    return to_return;
}

void *queue_peek(const queue_t *q)
{
    return q->head ? q->head->data : NULL;
}

void *queue_peek_any(const queue_t **q, int nq) {
    void *data = NULL;
    for (int i = 0; i < nq && !data; i++) {
        data = queue_peek(q[i]);
    }
    return data;
}

size_t queue_size(const queue_t *q)
{
    return q->size;
}