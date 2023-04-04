#ifndef OSX_SSL_VPN_CLIENT_MEM_H
#define OSX_SSL_VPN_CLIENT_MEM_H

#include <stdint.h>
#include <ntsid.h>


struct mem {
    pthread_mutex_t mutex;
    //pthread_cond_t cond;
    //uint32_t cancel_flag;
    uint32_t current_index;
    size_t num_chunks;

    struct mem_chunk *mem_chunks;
};

struct mem_chunk {
    unsigned int is_in_use;
    size_t chunk_size;
    size_t chunk_index;
    uint8_t *data;
};


int mem_init(size_t num_chunks, size_t chunk_size);

void mem_destroy();

struct mem_chunk *mem_aquire();

void mem_release(struct mem_chunk *chunk_to_release);

#endif //OSX_SSL_VPN_CLIENT_MEM_H
