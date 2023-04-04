/*
 * ppp_queue.c | ppp_queue.h
 * The ppp_queue-module
 *
 * Purpose:
 * Thread safe implementation of a queue,
 * which only supports pop and push of PPP_PACKETs.
 */

#include <stdlib.h>
#include "ppp_queue.h"
#include "log.h"

/*
 * Aquire the mutex & wait conditionally (i.e. with unlocked mutex)
 * until the new_data flag is raised & there is item(s) in the queue.
 */
struct PPP_PACKET *ppp_queue_pop(struct PPP_QUEUE *ppp_queue) {

    struct PPP_PACKET *queue_element;

    pthread_mutex_lock(&ppp_queue->mutex);

    while (ppp_queue->queue_head == NULL && !ppp_queue->cancel_flag) {
        pthread_cond_wait(&ppp_queue->new_data, &ppp_queue->mutex);
    }

    if (!ppp_queue->cancel_flag) {
        queue_element = ppp_queue->queue_head;
        ppp_queue->queue_head = queue_element->next_packet;
        queue_element->next_packet = NULL;
    } else {
        queue_element = NULL;
    }


    pthread_mutex_unlock(&ppp_queue->mutex);

    return queue_element;

}

/*
 * Aquire the mutex & append a PPP_PACKET to the end of the queue.
 * Abort if the cancel flag has been raised.
 */
void ppp_queue_push(struct PPP_QUEUE *ppp_queue, struct PPP_PACKET *ppp_packet) {

    struct PPP_PACKET *queue_element;

    pthread_mutex_lock(&ppp_queue->mutex);

    if (ppp_queue->cancel_flag) {
        log_error("PPP QUEUE PUSH: but cancel flag was set.");
        free(ppp_packet);
        pthread_mutex_unlock(&ppp_queue->mutex);
        return;
    }

    queue_element = ppp_queue->queue_head;

    ppp_packet->next_packet = NULL;

    if (queue_element == NULL) {
        ppp_queue->queue_head = ppp_packet;
    } else {
        while (queue_element->next_packet != NULL) {
            queue_element = queue_element->next_packet;
        }
        queue_element->next_packet = ppp_packet;
    }

    pthread_cond_signal(&ppp_queue->new_data);
    pthread_mutex_unlock(&ppp_queue->mutex);
}

/*
 * Signal that no new items should be added to the queue.
 */
void ppp_queue_cancel(struct PPP_QUEUE *ppp_queue) {
    pthread_mutex_lock(&ppp_queue->mutex);
    ppp_queue->cancel_flag = 1;
    pthread_cond_signal(&ppp_queue->new_data);
    pthread_mutex_unlock(&ppp_queue->mutex);
}


/*
 * Set up the mutex and its conditional.
 */
void ppp_queue_init(struct PPP_QUEUE *ppp_queue) {
    pthread_mutex_init(&ppp_queue->mutex, NULL);
    pthread_cond_init(&ppp_queue->new_data, NULL);
    ppp_queue->cancel_flag = 0;
    ppp_queue->queue_head = NULL;
}

/*
 * Destroy the mutex & free all items in the queue,
 * if there are any.
 */
void ppp_queue_terminate(struct PPP_QUEUE *ppp_queue) {
    pthread_mutex_destroy(&ppp_queue->mutex);

    struct PPP_PACKET *queue_element, *next_queue_element;

    queue_element = ppp_queue->queue_head;

    while (queue_element != NULL) {
        next_queue_element = queue_element->next_packet;

        free(queue_element);
        queue_element = next_queue_element;
    }

}