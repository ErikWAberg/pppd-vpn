#ifndef OSX_VPN_SSL_H
#define OSX_VPN_SSL_H

#include <pthread.h>
#include <openssl/ossl_typ.h>
#include <stdint.h>

#include "vpn.h"



struct SSL_CHANNEL {
    int ssl_socket;
    SSL_CTX *ssl_context;
    SSL *ssl_handle;
    struct STATS ssl_stats;

};

struct CRYPTO_dynlock_value {
    pthread_mutex_t mutex;
};


struct VPN;

int ssl_init(struct VPN *vpn);

int ssl_connect(struct VPN *vpn);

void* ssl_run_servlet(void *arg);

void ssl_disconnect(struct SSL_CHANNEL *ssl_channel);

int ssl_read(struct SSL_CHANNEL *ssl_channel, uint8_t *byte_buffer, int num_bytes);

int ssl_read_n(struct SSL_CHANNEL *ssl_channel, uint8_t *byte_buffer, int buffer_size);

int ssl_write(struct SSL_CHANNEL *ssl_channel, uint8_t *byte_buffer, int num_bytes);

int ssl_verify_fingerprint(struct VPN* vpn);

void *ssl_writer(void *arg);

void *ssl_reader(void *arg);


#endif
