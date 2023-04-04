#include "../vpn.h"
#include "../mem.h"
#include "../log.h"
#include <stdio.h>

volatile int stop = 0;

void *producer(void *arg) {
    struct mem_chunk *chunk;
    uint8_t count = 0;
    while(!stop) {
        chunk = mem_aquire();

        for(size_t i = 0; i < chunk->chunk_size; i++) {
            chunk->data[i] =  count; //(count + i);
        }
        mem_release(chunk);
        usleep(100*1000);
        count+= 1;
        log_info("count= %d\n", count);
        if(count == 0) {stop = 1; break;}
    }

    return NULL;
}

void *consumer(void *arg) {
    struct mem_chunk *chunk;
    while(!stop) {
        chunk = mem_aquire();
        for(size_t i = 0; i < chunk->chunk_size; i++) {
            printf(" %d ", chunk->data[i]);
            chunk->data[i] = 0;
        }
        printf("\n");
        mem_release(chunk);
        usleep(50*1000);
    }
    return NULL;
}
sem_t sem;

int main(int argc, char *argv[]) {
    sem_init(&sem, 0, 0);
    log_init(1);
    mem_init(1, 10);
    pthread_t prod, cons;
    pthread_create(&prod, NULL, producer, NULL);
    pthread_create(&cons, NULL, consumer, NULL);
   /* struct mem_chunk *chunk;
    for(int i = 0; i < 8; i++) {
        chunk = mem_aquire();
        chunk->data[0] = 1 + i;
        chunk->data[1] = 2 + i;
        mem_release(chunk);
    }
    for(int i = 0; i < 8; i++) {
        chunk = mem_aquire();
        printf("Data(%d): %d%d\n", i, chunk->data[0], chunk->data[1]);
        mem_release(chunk);
    }*/
    sem_wait(&sem);
    pthread_join(prod, NULL);
    pthread_join(cons, NULL);
    mem_destroy();
}
