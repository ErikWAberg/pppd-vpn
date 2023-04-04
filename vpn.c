/*
 * vpn.c | vpn.h
 * The vpn-module
 *
 * Purpose:
 *  - Initiates the VPN structures, threads etc.
 *  - Provide API for GUI
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <limits.h>
#include <getopt.h>

#include "vpn.h"
#include "log.h"
#include "definitions.h"
#include "utils.h"
#include "ssl.h"



#ifndef __APPLE__
#include <fcntl.h>
#include <wait.h>
#endif

private void vpn_print_usage(char* argv[]);

private void vpn_print_io_stats();

private void vpn_signal_handler(int sig);

private int vpn_construct(struct VPN *vpn);

private void vpn_destruct(struct VPN *vpn);

private int vpn_init_threads(struct VPN *vpn);

private void vpn_terminate_threads(struct VPN *vpn);

private int vpn_server(void);

global_variable struct VPN vpn = {0};

//----------------------------------------------------------------------------------------
// VPN - EXTERNAL API
// Called from external GUI applications or similar.
//----------------------------------------------------------------------------------------

/*
 * Called when the VPN program is started from a terminal.
 * Arguments passed to the program is parsed.
 * The VPN is then initiated with the configuration file
 * provided by the user via the cmd-args.
 * Given that all required options were provided, we
 * immediately attempt to connect to the VPN server.
 */
int vpn_run_cli(int argc, char **argv) {

    char* configuration_file = NULL, *password = NULL;

    int opt, fd, log_level = LOG_NONE;
    uintmax_t convertedLogLevel;

    while ((opt = getopt(argc, argv, "l:x:p:sc")) != -1) {
        switch (opt) {
            case 'l':
                convertedLogLevel = strtoul(optarg, NULL, 10);

                if ((convertedLogLevel == ULONG_MAX && errno == ERANGE)) {
                    fprintf(stderr, "VPN: Can't convert '%s' to a number in range [0-2] - '%s'\n", optarg, strerror(errno));
                    vpn_print_usage(argv);
                    exit(EXIT_FAILURE);
                }
                log_level = (int) convertedLogLevel;

                if(log_level < LOG_NONE || log_level > LOG_DATA) {
                    fprintf(stderr, "VPN: Log level not in range [0, 2] - defaulting to 0\n");
                    log_level = LOG_NONE;
                }

                break;

            case 'x':
                if ((fd = open(optarg, O_RDONLY, 0)) < 0) {
                    fprintf(stderr, "VPN: Cant open configuration file: %s: %s\n", optarg, strerror(errno));
                    vpn_print_usage(argv);
                    exit(EXIT_FAILURE);
                }
                close(fd);
                configuration_file = optarg;

                break;

            case 'p':
                password = optarg;
                break;

            case 's':
                vpn.server_mode = true;
                break;

            case 'c':
                vpn.client_mode = true;
                break;

            case '?':
            default:
                vpn_print_usage(argv);
                exit(EXIT_FAILURE);
        }
    }
    argc -= optind;
    argv += optind;

    if(vpn_init_with_file(log_level, configuration_file) != 0) {
        exit(EXIT_FAILURE);
    }

    if(!password) {
        printf("Input password:");
        password = util_get_input_string();
        printf("\n");
    }

    if(password) {
        strcpy(vpn.vpn_config->user_password, password);
    } else {
        log_error("VPN: No password given");
        return EXIT_FAILURE;
    }

    if(vpn.server_mode) {
        return vpn_server();
    }
    return vpn_connect();
}

/*
 * Initiates the VPN-struct based on the contents of a
 * configuration file.
 */
int vpn_init_with_file(int log_level, char *config_file) {

    if(log_level > LOG_DATA || log_level < LOG_NONE) {
        fprintf(stderr, "VPN: Log level not in range [0, 2] - defaulting to 0\n");
        log_init(LOG_NONE);
    } else {
        log_init(log_level);
    }

    vpn.external_vpn_config = false;

    if(vpn_construct(&vpn) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if(config_file) {
        if(config_read(vpn.vpn_config, config_file) != EXIT_SUCCESS) {
            log_error("VPN: Failed to read configuration file.");
            goto err_exit;
        }

    } else {
        log_error("VPN: Null-pointer to configuration file.");
        goto err_exit;
    }

    return EXIT_SUCCESS;

    err_exit:

    vpn_destruct(&vpn);
    return EXIT_FAILURE;
}

/*
 * If we already have parsed a configuration file, possibly
 * via some GUI application using this library,
 * this function may be called from an external program
 * to initiate the VPN-struct & bind to it the provided
 * VPN configuration.
 */
int vpn_init_with_configuration(int log_level, struct VPN_CONFIG *vpn_config) {

    if(log_level > LOG_DATA || log_level < LOG_NONE) {
        fprintf(stderr, "VPN: Log level not in range [0, 2] - defaulting to 0");
        log_init(LOG_NONE);
    } else {
        log_init(log_level);
    }

    if(!vpn_config) {
        log_error("VPN: Got null-pointer to arg 'vpn_config'");
        return EXIT_FAILURE;
    }

    vpn.external_vpn_config = true;
    vpn.vpn_config = vpn_config;

    if(vpn_construct(&vpn) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


/*
 * Initiates the VPN:
 * - Attempt to create an SSL connection.
 * - Verify the server fingerprint.
 * - Initiate the PPP-daemon.
 * - Send 'initiation' message to VPN server.
 * - Initiate threads handling reading/writing.
 * - Wait for threads to terminate.
 * - De-alloc allocated data.
 */
int vpn_connect(void) {

    vpn_set_state(&vpn, VPN_CONNECTING);

    if (ssl_init(&vpn) != 0) {
        goto err_ssl;
    }

    if(ssl_connect(&vpn) != 0) {
        goto err_ssl;
    }


    if(!vpn.client_mode)
    if(ssl_verify_fingerprint(&vpn) != EXIT_SUCCESS) {
        goto err_ssl;
    }

    ppp_init(&vpn);

    if(!vpn.client_mode) {
        log_info("VPN: Sending HELLO to VPN server.");

        int w = ssl_write(vpn.ssl_channel, (uint8_t *) "SSLVPN 1.0\n\n", 13);

        if (w != 13) {
            log_error("VPN: Could not contact server, quitting.");
            goto err_ssl;
        } else {
            log_info("VPN: Server accepted HELLO message.");
        }
    }

    if (vpn_init_threads(&vpn) != EXIT_SUCCESS) {
        log_error("VPN: Failed to initialize threads, quitting.");
        goto err_threads;
    }


    //Setting up signal handler after initiating threads.
    signal(SIGINT, vpn_signal_handler);

#ifdef PPP_INFO_SCRIPT
    while(vpn.vpn_state == VPN_CONNECTING) {
        usleep(5000 * 1000);
    }
    if(vpn.vpn_state == VPN_CONNECTED) {
        log_info("VPN: Showing PPP service info:");
        system(PPP_INFO_SCRIPT);
    }
#endif

    //Wait for termination semaphore
    sem_wait(&vpn.sem_terminate);

    //------- BARRIER -------------------------


    vpn_print_io_stats();

    vpn_set_state(&vpn, VPN_DISCONNECTED);

    ppp_queue_cancel(vpn.pppd_to_ssl_queue);
    ppp_queue_cancel(vpn.ssl_to_pppd_queue);

    vpn_terminate_threads(&vpn);
    ssl_disconnect(vpn.ssl_channel);
    vpn_destruct(&vpn);

    log_info("VPN: Terminated.");
    return EXIT_SUCCESS;


    err_ssl:

    log_error("VPN: SSL error, exiting.");

    ssl_disconnect(vpn.ssl_channel);
    vpn_destruct(&vpn);

    log_info("VPN: Terminated.");
    return EXIT_FAILURE;

    err_threads:

    log_error("VPN: Could not initialize threads, exiting.");

    ssl_disconnect(vpn.ssl_channel);
    vpn_destruct(&vpn);

    log_info("VPN: Terminated.");
    return EXIT_FAILURE;
}

void vpn_server_state_callback(int client_connected) {
    if(client_connected == 1337) {
        log_info("A client connected to the server socket, starting pppd & threads.");
        ppp_init(&vpn);
        if (vpn_init_threads(&vpn) != EXIT_SUCCESS) {
            log_error("VPN: Failed to initialize threads, quitting.");
        }
    }
}

//Creater for client to client connection
//Similar to vpn_connect
int vpn_server(void) {

    if (ssl_init(&vpn) != 0) {
        goto err_ssl;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, ssl_run_servlet, &vpn))
        return EXIT_FAILURE;

    vpn_set_state_callback(vpn_server_state_callback);


    //Setting up signal handler after initiating threads.
    signal(SIGINT, vpn_signal_handler);

    //Wait for termination semaphore
    sem_wait(&vpn.sem_terminate);

    //------- BARRIER -------------------------


    vpn_print_io_stats();

    ppp_queue_cancel(vpn.pppd_to_ssl_queue);
    ppp_queue_cancel(vpn.ssl_to_pppd_queue);

    vpn_terminate_threads(&vpn);
    ssl_disconnect(vpn.ssl_channel);
    vpn_destruct(&vpn);

    log_info("VPN: Terminated.");
    return EXIT_SUCCESS;


    err_ssl:

    log_error("VPN: SSL error, exiting.");

    ssl_disconnect(vpn.ssl_channel);
    vpn_destruct(&vpn);

    log_info("VPN: Terminated.");
    return EXIT_FAILURE;

}


/*
 * Called from external program to terminate
 * the VPN connection.
 */
void vpn_terminate(void) {
    vpn_signal_handler(SIGINT);
}

/*
 * An external program may want to get a
 * notification upon state-changes of the VPN.
 * The function passed to this function will be called
 * upon changes of the VPN state.
 */
void vpn_set_state_callback(void (*state_callback_func)(int)) {
    vpn.vpn_state_callback = state_callback_func;
}

/*
 * Retrieve the current state of the VPN.
 */
int vpn_get_state(void) {
    return vpn.vpn_state;
}

/*
 * Retrieve our new local ip as given
 * by the VPN server.
 */
char* vpn_get_local_ip(void) {
    local_persist char* local_ip = NULL;
    if(vpn.pppd) {
        local_ip = inet_ntoa(vpn.pppd->ip_local);
    }
    return local_ip;
}

/*
 * Retrieve the VPN gateway ip.
 */
char* vpn_get_remote_ip(void) {
    local_persist char* remote_ip = NULL;
    if(vpn.vpn_config) {
        remote_ip = inet_ntoa(vpn.pppd->ip_remote);
    }
    return remote_ip;
}

/*
 * Retrieve our new primary DNS as given
 * by the VPN server.
 */
char* vpn_get_primary_dns(void) {
    local_persist char* primary_dns = NULL;
    if(vpn.pppd) {
        primary_dns = inet_ntoa(vpn.pppd->ip_dns1);
    }
    return primary_dns;
}

/*
 * Retrieve our new secondary DNS as given
 * by the VPN server.
 */
char* vpn_get_secondary_dns(void) {
    local_persist char* secondary_dns = NULL;
    if(vpn.pppd) {
        secondary_dns = inet_ntoa(vpn.pppd->ip_dns2);
    }
    return secondary_dns;
}

/*
 * Retrieve the number of bytes that we
 * have received on the SSL connection.
 */
uint64_t vpn_get_bytes_received(void) {
    if(vpn.ssl_channel) {
        return vpn.ssl_channel->ssl_stats.byte_count_in;
    }
    return 0;
}

/*
 * Retrieve the number of bytes that we
 * have sent on the SSL connection.
 */
uint64_t vpn_get_bytes_sent(void) {
    if(vpn.ssl_channel) {
        return vpn.ssl_channel->ssl_stats.byte_count_out;
    }
    return 0;
}

int vpn_config_read(struct VPN_CONFIG *vpn_config, const char *config_file) {
    return config_read(vpn_config, config_file);
}

//----------------------------------------------------------------------------------------
// VPN - CONSTRUCTORS AND DESTRUCTORS & HELPER FUNCTIONS
//----------------------------------------------------------------------------------------
/*
 * Set the current state of the VPN and notify the
 * change via the callback function - if one was set.
 */
void vpn_set_state(struct VPN* vpn, enum VPN_STATE vpn_state) {
    if(vpn) {
        vpn->vpn_state = vpn_state;
        if(vpn->vpn_state_callback) {
            vpn->vpn_state_callback(vpn_state);
        }
    }
}

/*
 * Print out usage information to the user.
 */
private void vpn_print_usage(char* argv[]) {
    fprintf(stderr, "Usage: %s [-l log_level{0-3}] [-x config_file] [-s/c (aka. server/client)]\n", argv[0]);
}

private void vpn_print_io_stats() {
    uint64_t bytes_in = vpn.ssl_channel->ssl_stats.byte_count_in;
    uint64_t bytes_out = vpn.ssl_channel->ssl_stats.byte_count_out;
    log_info("STATS: RX: %.2f MB", (float) bytes_in / (1000 * 1000.0));
    log_info("STATS: TX: %.2f MB", (float) bytes_out / (1000 * 1000.0));
}

private void vpn_signal_handler(int signal) {
    vpn_set_state(&vpn, VPN_DISCONNECTED);

    log_info("VPN: Received signal %d, terminating.", signal);
    if(vpn.sem_terminate) {
        sem_post(&vpn.sem_terminate);
    }

}


private int vpn_construct(struct VPN *vpn) {
    log_info("VPN: Initializing...");

    if(!vpn->external_vpn_config) {
        vpn->vpn_config = malloc(sizeof(struct VPN_CONFIG));
        if(!vpn->vpn_config) {
            log_error("VPN: Failed to allocate VPN_CONFIG\n");
            return ERR_ALLOC;
        }
    }

    vpn->pppd = malloc(sizeof(struct PPPD));

    if (vpn->pppd == NULL) {
        log_error("VPN: Failed to allocate PPPD\n");
        return ERR_ALLOC;
    }
    memset(&vpn->pppd->ip_local, 0, sizeof(uint8_t) * 4);
    memset(&vpn->pppd->ip_remote, 0, sizeof(uint8_t) * 4);
    memset(&vpn->pppd->ip_dns1, 0, sizeof(uint8_t) * 4);
    memset(&vpn->pppd->ip_dns2, 0, sizeof(uint8_t) * 4);

    sem_init(&vpn->sem_terminate, 0, 0);



    vpn->pppd_to_ssl_queue = malloc(sizeof(struct PPP_QUEUE));
    vpn->ssl_to_pppd_queue = malloc(sizeof(struct PPP_QUEUE));

    ppp_queue_init(vpn->pppd_to_ssl_queue);
    ppp_queue_init(vpn->ssl_to_pppd_queue);

    vpn_set_state(vpn, VPN_DISCONNECTED);

    return 0;

}

private void vpn_destruct(struct VPN *vpn) {
    log_info("VPN: Freeing memory...");

    if(!vpn->external_vpn_config) {
        free(vpn->vpn_config);
    }

    if(vpn->pppd) {
        kill(vpn->pppd->pid, SIGINT);
        close(vpn->pppd->pty);
        log_info("Waiting for pppd to exit...");
        waitpid(vpn->pppd->pid, NULL, 0);
        free(vpn->pppd);
    }

    sem_destroy(&vpn->sem_terminate);

    ppp_queue_terminate(vpn->pppd_to_ssl_queue);
    ppp_queue_terminate(vpn->ssl_to_pppd_queue);

    free(vpn->pppd_to_ssl_queue);
    free(vpn->ssl_to_pppd_queue);

}

private int vpn_init_threads(struct VPN *vpn) {
    log_info("VPN: Initializing threads...");
    if (pthread_create(&vpn->ppp_read_thread, NULL, ppp_reader, vpn))
        return EXIT_FAILURE;
    if (pthread_create(&vpn->ppp_write_thread, NULL, ppp_writer, vpn))
        return EXIT_FAILURE;
    if (pthread_create(&vpn->ssl_read_thread, NULL, ssl_reader, vpn))
        return EXIT_FAILURE;
    if (pthread_create(&vpn->ssl_write_thread, NULL, ssl_writer, vpn))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}


private void vpn_terminate_threads(struct VPN *vpn) {
    log_info("VPN: Terminating threads...");

    pthread_cancel(vpn->ssl_write_thread);
    pthread_cancel(vpn->ssl_read_thread);
    pthread_cancel(vpn->ppp_write_thread);
    pthread_cancel(vpn->ppp_read_thread);

    pthread_join(vpn->ssl_write_thread, NULL);
    pthread_join(vpn->ssl_read_thread, NULL);
    pthread_join(vpn->ppp_write_thread, NULL);
    pthread_join(vpn->ppp_read_thread, NULL);
}


