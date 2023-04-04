#ifndef OSX_VPN_PPP_QUEUE_H
#define OSX_VPN_PPP_QUEUE_H

#include "ppp.h"
#include <pthread.h>

struct PPP_QUEUE {
	pthread_mutex_t mutex;
	pthread_cond_t new_data;
	struct PPP_PACKET* queue_head;
	int cancel_flag;
};

struct PPP_PACKET* ppp_queue_pop(struct PPP_QUEUE* ppp_queue);
void ppp_queue_push(struct PPP_QUEUE* ppp_queue, struct PPP_PACKET* ppp_packet);
void ppp_queue_cancel(struct PPP_QUEUE *ppp_queue);
void ppp_queue_init(struct PPP_QUEUE* ppp_queue);
void ppp_queue_terminate(struct PPP_QUEUE* ppp_queue);

#endif