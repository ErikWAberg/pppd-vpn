#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/errno.h>
#include "mem.h"
#include "definitions.h"
#include "log.h"

global_variable struct mem memory;

int mem_init(size_t num_chunks, size_t chunk_size) {
    log_info("mem: Allocating memory chunks...");

    memory.current_index = 0;
    memory.num_chunks = num_chunks;

    pthread_mutex_init(&memory.mutex, NULL);
    //pthread_cond_init(&memory.cond, NULL);

    memory.mem_chunks = calloc(num_chunks, sizeof(struct mem_chunk));
    if(!memory.mem_chunks) {
        log_error("mem: Not enough memory for allocating chunks.");
        return errno;
    }

    for(size_t i = 0; i < num_chunks; i++) {
        memory.mem_chunks[i].data = malloc(chunk_size);
        if(!memory.mem_chunks[i].data) {
            log_error("mem: Not enough memory for allocating chunk.");
            return errno;
        }
        memory.mem_chunks[i].chunk_size = chunk_size;
        memory.mem_chunks[i].is_in_use = false;
        memory.mem_chunks[i].chunk_index = i;
    }

    return 0;
}

void mem_destroy() {
    log_info("mem: Destroying memory chunks...");

    pthread_mutex_lock(&memory.mutex);

    for(size_t i = 0; i < memory.num_chunks; i++) {
        free(memory.mem_chunks[i].data);
    }
    free(memory.mem_chunks);
    memory.num_chunks = 0;

    pthread_mutex_unlock(&memory.mutex);
    pthread_mutex_destroy(&memory.mutex);
    //TODO destroy mutex
}

struct mem_chunk *mem_aquire() {
    struct mem_chunk *aquired_mem;

    pthread_mutex_lock(&memory.mutex);

    aquired_mem = &memory.mem_chunks[memory.current_index];
    if(aquired_mem->is_in_use) {
        log_error("mem: MEM ALREADY IN USE, index == %d", memory.current_index);
        exit(0);
    }

    aquired_mem->is_in_use = true;
    memory.current_index += 1;
    memory.current_index %= memory.num_chunks;

    pthread_mutex_unlock(&memory.mutex);

    return aquired_mem;
}


void mem_release(struct mem_chunk *chunk_to_release) {
    pthread_mutex_lock(&memory.mutex);
    chunk_to_release->is_in_use = false;
    pthread_mutex_unlock(&memory.mutex);
}