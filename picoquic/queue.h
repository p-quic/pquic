/**
 * \file queue.h
 * \author Quentin De Coninck
 * \brief A simple implementation of a queue using linked-list.
 * 
 * Queue using two pointers, head and tail, and a simple linked list
 * to the next element being removed. Node memory is managed by this
 * simple library.
 * 
 * \warning Insertion of NULL element is discouraged, as it would not be possible to distinguish at peeking and dequeueing
 * if the element is NULL or if the queue is empty.
 */

/**
 * A node of the queue.
 */
typedef struct queue_node {
    void *data;
    struct queue_node *next;
} queue_node_t;

/**
 * The queue containing references to the first (for removal) and the
 * last (fast insertion) elements.
 */
typedef struct queue {
    queue_node_t *head;
    queue_node_t *tail;
    size_t size;
} queue_t;

/**
 * Initialize and get a queue structure.
 * 
 * \return Pointer to the initialized, empty queue, or NULL if there was memory issues.
 */
queue_t *queue_init();

/**
 * Free all resources of the queue. The queue is then unusable.
 * If the queue is not empty, its elements are removed and free'd.
 * \param[in] q The queue to free memory.
 */
void queue_free(queue_t *q);

/**
 * Enqueue the data \p d in the queue \p q.
 * \param[in] q The queue in which the element will be enqueued.
 * \param[in] d The data to enqueue. \warning Insertion of NULL element is discouraged.
 * \return 0 if everything is fine. If an error occurs (e.g., memory allocation failure), returns a non-zero value.
 */
int queue_enqueue(queue_t *q, void *d);

/**
 * Dequeue the first element in the queue \p q and free internal structure used to maintain this element in \p q.
 * \param[in] q The queue to dequeue the first element.
 * 
 * \return The data contained in the first element of the queue, or NULL if there is no such element.
 */
void *queue_dequeue(queue_t *q);

/**
 * Peek the first element in the queue \p q. \p q is not modified.
 * \param[in] q The queue to peek the first element.
 * 
 * \return The data contained in the first element of the queue.
 */
void *queue_peek(const queue_t *q);

/**
 * Peek the first element in any of the queues in \p q. \p q is not modified.
 * \param[in] q An array of queues.
 * \param[in] nq The number of queues in q. Must be positive.
 *
 * \return The data contained in the first non-null element of the queue.
 */
void *queue_peek_any(const queue_t **q, int nq);

/**
 * Get the number of elements in the queue.
 * \param[in] q The queue to get the size.
 *
 * \return The number of elements in the queue.
 */
size_t queue_size(const queue_t *q);