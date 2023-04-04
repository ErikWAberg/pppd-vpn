#ifndef OSX_VPN_VPN_H
#define OSX_VPN_VPN_H


#include "ppp.h"
#include "config.h"
#include "ppp_queue.h"
#include <stdbool.h>

#ifdef __APPLE__

#include <dispatch/dispatch.h>

typedef dispatch_semaphore_t sem_t;

#define sem_init(psem, x, val)  *psem = dispatch_semaphore_create(val)
#define sem_post(psem)          dispatch_semaphore_signal(*psem)
#define sem_wait(psem)          dispatch_semaphore_wait(*psem, DISPATCH_TIME_FOREVER)
#define sem_destroy(psem)       dispatch_release(*psem)

#else
#include <semaphore.h>
#endif

enum VPN_STATE {
    VPN_DISCONNECTED,
    VPN_CONNECTING,
    VPN_CONNECTED,
    VPN_ERROR
};


struct VPN {
    bool server_mode;   //Accept incomming SSL sessions
    bool client_mode;   //Connect to a server instance of this program
    bool external_vpn_config;

    struct VPN_CONFIG *vpn_config;

    enum VPN_STATE vpn_state;
    struct SSL_CHANNEL *ssl_channel;
    struct PPPD *pppd;

    struct PPP_QUEUE *ssl_to_pppd_queue;
    struct PPP_QUEUE *pppd_to_ssl_queue;

#ifdef __APPLE__
    //In order to play ball with Objective-C
    __unsafe_unretained sem_t sem_terminate;
#else
    sem_t sem_terminate;
#endif

    pthread_t ppp_read_thread;
    pthread_t ppp_write_thread;
    pthread_t ssl_read_thread;
    pthread_t ssl_write_thread;

    void (*vpn_state_callback)(int);

} VPN;

struct STATS {
    uint64_t byte_count_in;
    uint64_t byte_count_out;
};


void vpn_set_state(struct VPN* vpn, enum VPN_STATE vpn_state);

int vpn_run_cli(int argc, char **argv);

int vpn_init_with_file(int log_level, char *config_file);

//API

int vpn_config_read(struct VPN_CONFIG *vpn_config, const char *config_file);

int vpn_init_with_configuration(int log_level, struct VPN_CONFIG *vpn_config);

void vpn_set_state_callback(void (*state_callback_func)(int));

int vpn_connect(void);

void vpn_terminate(void);

int vpn_get_state(void);

char* vpn_get_local_ip(void);

char *vpn_get_remote_ip(void);

char *vpn_get_primary_dns(void);

char *vpn_get_secondary_dns(void);

uint64_t vpn_get_bytes_received(void);

uint64_t vpn_get_bytes_sent(void);

#endif
