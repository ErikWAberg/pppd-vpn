/*
 * ssl.c | ssl.h
 * The ssl-module
 *
 * Purpose:
 *
 *
 */

#include <stdio.h>
#include <unistd.h>

#include <pthread.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/rand.h>

#ifdef __APPLE__

#include <resolv.h>

#endif

#include "ssl.h"
#include "socket.h"
#include "log.h"
#include "definitions.h"


private void ssl_locking_function(int mode, int n, const char *file, int line);

private unsigned long ssl_id_function(void);

private struct CRYPTO_dynlock_value *ssl_dyn_create_function(const char *file, int line);

private void ssl_dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l,
                                  const char *file, int line);

private void ssl_dyn_destroy_function(struct CRYPTO_dynlock_value *l,
                                     const char *file, int line);

private int ssl_init_locking(void);

private int ssl_cleanup_locking(void);

private void ssl_reset_stats(struct SSL_CHANNEL *ssl_channel);


//----------------------------------------------------------------------------------------
// SSL I/O thread entry functions
//----------------------------------------------------------------------------------------

/*
 * SSL Writer, thread entry function.
 * Continually tries to grab a PPP packet from the pppd_to_ssl queue
 * and then writes it onto the SSL socket.
 * (This is the only consumer of that queue,
 * the producer is forwarding output from the ppp-daemon
 * onto this queue)
 */
void *ssl_writer(void *arg) {
    struct VPN *vpn = (struct VPN *) arg;

    while (1) {

        struct PPP_PACKET *ppp_packet;
        int bytes_written = 0;

        ppp_packet = ppp_queue_pop(vpn->pppd_to_ssl_queue);

        if (ppp_packet == NULL) {
            if(vpn->pppd_to_ssl_queue->cancel_flag) {
                log_error("SSL-Writer: got null package due to cancel flag, quitting.");
                break;
            }
            log_error("SSL-Writer: Got null ppp-package, continuing!");
            continue;
        }

        if (ppp_packet->num_bytes <= 0) {
            log_error("SSL-Writer: Got empty package, continuing...");
            free(ppp_packet);
            continue;
        }

        ppp_insert_header(ppp_packet);
        ppp_packet->num_bytes += PPP_HEADER_SIZE;

        bytes_written = ssl_write(vpn->ssl_channel, ppp_packet->data,
                                  ppp_packet->num_bytes);

        if (bytes_written <= 0 || bytes_written != ppp_packet->num_bytes) {
            log_error("SSL-Writer: Failed to write on SSL socket (%d != %d).",
                      bytes_written, ppp_packet->num_bytes);
            free(ppp_packet);
            break;
        }

        vpn->ssl_channel->ssl_stats.byte_count_out += bytes_written;
        log_txrx("SSL-Writer: Wrote %d bytes.", ppp_packet->num_bytes);
        log_data("SSL-Writer: ppp-packet data", ppp_packet->data, ppp_packet->num_bytes);

        free(ppp_packet);

    }

    log_error("SSL-Writer: signaling termination");
    sem_post(&vpn->sem_terminate);
    return NULL;
}

/*
 * SSL Reader, thread entry function.
 * Continually tries to read from the SSL socket.
 * Once a complete PPP package has been read from the socket,
 * it is placed in the ssl_to_pppd queue.
 * (The ssl_to_pppd_queue consumer then writes the package
 * to the ppp-daemon)
 */
void *ssl_reader(void *arg) {
    struct VPN *vpn = (struct VPN *) arg;

    while (1) {
        int bytes_read = 0;
        uint8_t header[PPP_HEADER_SIZE];
        uint32_t magic, packet_length;
        struct PPP_PACKET *ppp_packet;

        bytes_read = ssl_read_n(vpn->ssl_channel, &header[0], PPP_HEADER_SIZE);

        if (bytes_read <= 0) {
            log_error("SSL-Reader: Failed to read from SSL socket. %d", bytes_read);
            break;
        }

        magic = ntohl(*(uint32_t *) &header[0]);
        packet_length = ntohl(*(uint32_t *) &header[4]);

        if (magic != PPP_MAGIC) {
            log_error("SSL-Reader: Received non-valid PPP Magic %08x", magic);
            break;
        }

        ppp_packet = malloc(sizeof(struct PPP_PACKET) + packet_length);

        if (ppp_packet == NULL) {
            log_error("SSL-Reader: Packet malloc failed");
            break;
        }

        ppp_packet->num_bytes = packet_length;

        bytes_read = ssl_read_n(vpn->ssl_channel, ppp_packet->data, ppp_packet->num_bytes);

        if (bytes_read != packet_length) {
            log_error("SSL-Reader: Read %d bytes, should have read %d bytes", bytes_read, ppp_packet->num_bytes);
            break;
        }
        vpn->ssl_channel->ssl_stats.byte_count_in += bytes_read;

        log_txrx("SSL-Reader: Read %d bytes.", ppp_packet->num_bytes);
        log_data("SSL-Reader: DATA", ppp_packet->data, ppp_packet->num_bytes);
        ppp_queue_push(vpn->ssl_to_pppd_queue, ppp_packet);
    }

    log_error("SSL READ failed, signaling termination.");
    sem_post(&vpn->sem_terminate);
    return NULL;
}


//----------------------------------------------------------------------------------------
// SSL I/O API
//----------------------------------------------------------------------------------------

/*
 * Attempts to read 'n' bytes from an SSL_CHANNEL by calling
 * 'ssl_read' until 'n' bytes have been read.
 * If there was an error reading, it may not necessarily mean
 * that the underlying connection has been terminated -
 * so we must check the error code and see whether there
 * SSL want us to re-read.
 */
int ssl_read_n(struct SSL_CHANNEL *ssl_channel, uint8_t *byte_buffer, int buffer_size) {
    int num_read, num_read_total = 0;

    while (num_read_total < buffer_size) {
        num_read = ssl_read(ssl_channel, byte_buffer, buffer_size - num_read_total);

        if (num_read > 0) {
            num_read_total += num_read;
        } else {
            int err_code = SSL_get_error(ssl_channel->ssl_handle, num_read);
            log_error("SSL READ ERROR: %d, num read: %d", err_code, num_read);

            if (err_code == SSL_ERROR_WANT_READ) {
                continue;
            } else if (err_code == SSL_ERROR_ZERO_RETURN) {
                log_error("SSL WAS CLOSED");
            }

            return num_read;
        }
    }
    return num_read_total;
}

/*
 * Attempts to read 'num_bytes' from an SSL_CHANNEL - may read less than
 * 'num_bytes', see 'ssl_read_n'.
 */
int ssl_read(struct SSL_CHANNEL *ssl_channel, uint8_t *byte_buffer, int num_bytes) {
    int num_read;

    num_read = SSL_read(ssl_channel->ssl_handle, byte_buffer, num_bytes);

    return num_read;
}

/*
 * Write num_bytes of bytes to the SSL_CHANNEL.
 */
int ssl_write(struct SSL_CHANNEL *ssl_channel, uint8_t *byte_buffer, int num_bytes) {
    int num_written = 0;
    int tries = 0;

    while (num_written == 0 && tries < 5) {
        num_written = SSL_write(ssl_channel->ssl_handle, byte_buffer, num_bytes);
        tries++;
    }

    if (num_written > 0) {
        return num_written;
    }

    log_error("SSL WRITE ERROR %d, nr of tries: %d", num_written, tries);

    return num_written;
}



//----------------------------------------------------------------------------------------
// SSL SETUP - Connect/Disconnect
//----------------------------------------------------------------------------------------

/*
 * Compares the fingerprint read from the configuration file
 * which is stored in the vpn->vpn_config, against the
 * fingerprint that we receive from the server.
 * If the fingerprints don't match, we eventually disconnect
 * from the server as we don't trust it.
 */
int ssl_verify_fingerprint(struct VPN* vpn) {
    X509 *cert;

    if ((cert = SSL_get_peer_certificate(vpn->ssl_channel->ssl_handle)) == NULL) {
        log_error("SSL: Could not get a certificate from server.");
    }

    log_info("SSL: Verifying certificate fingerprint...");

    unsigned char szFingerprint[EVP_MAX_MD_SIZE];
    unsigned int uFingerprintLen;
    X509_digest(cert, EVP_sha1(), szFingerprint, &uFingerprintLen);

    char fingerprintHex[EVP_MAX_MD_SIZE];
    int index = 0;
    for(int i = 0; i < uFingerprintLen; i++) {
        index += sprintf(&fingerprintHex[index], "%02x%c", szFingerprint[i], (i != uFingerprintLen - 1 ? ':' : '\0'));
    }
    log_info("SSL: Comparing stored fingerprint:\n%s\nvs fingerprint of server:\n%s",
              vpn->vpn_config->server_ssl_fingerprint, fingerprintHex);

    X509_free(cert);

    if(strcmp(fingerprintHex, vpn->vpn_config->server_ssl_fingerprint) != 0) {
        log_error("SSL: Fingerprint missmatch, not trusting server.");
        return -1;
    }

    log_info("SSL: Fingerprint verified.");

    return 0;
}

/*
 * Set up the negotiation options before attempting
 * to connect to a server.
 * We specifically want the highest SSL/TLS version available,
 * therefore disabling SSL version 2 & 3 for negotiation,
 * and request the SSL library to handle re-connections & handshakes
 * automatically in the background.
 * We also specify a set of available ciphers.
 */
private int ssl_create_context(struct SSL_CHANNEL *ssl_channel, bool server_mode) {

    //Negotiate the highest available SSL/TLS version.

   // SSLe
    const SSL_METHOD *ssl_method;

    if(server_mode)
        ssl_method = SSLv23_server_method();
    else
        ssl_method = SSLv23_client_method();


    if ((ssl_channel->ssl_context = SSL_CTX_new(ssl_method)) == NULL) {
        log_error("Failed to create SSL context.");
        return -1;
    }

    // Disabling SSLv2 & v3 will leave TSLv1.x for negotiation
    SSL_CTX_set_options(ssl_channel->ssl_context, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    // Perform reconnects in background
    SSL_CTX_set_mode(ssl_channel->ssl_context, SSL_MODE_AUTO_RETRY);

    if (!SSL_CTX_set_cipher_list(ssl_channel->ssl_context, "ALL:EXP:!aNULL:!eNULL:!SSLv2")) {
        log_error("Failed to set cipher list.");
        return -1;
    }

    return 0;
}

void ssl_servlet_certificates(SSL_CTX* ctx, char* cert_file, char* key_file) {

    if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ) {
        log_error("Failed to use certificate file, errno: %d=%s", errno, strerror(errno));
        ERR_print_errors_fp(stderr);
        abort();
    }

    if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 ) {
        log_error("Failed to use private-key file, errno: %d=%s", errno, strerror(errno));
        ERR_print_errors_fp(stderr);
        abort();
    }

    if ( !SSL_CTX_check_private_key(ctx) ) {
        log_error("Private key does not match the public certificate");
        abort();
    }
}

void* ssl_run_servlet(void* arg) {
    struct VPN *vpn = (struct VPN*) arg;
    system("echo `pwd`");
    ssl_servlet_certificates(vpn->ssl_channel->ssl_context, "cert.pem", "key.pem");

    log_info("SSL: Waiting for incoming connection...");
    vpn->ssl_channel->ssl_socket = socket_open_listener(vpn->vpn_config->server_port);

    while (1) {
        struct sockaddr_in addr;
        int len = sizeof(addr);

        int client = accept(vpn->ssl_channel->ssl_socket, (struct sockaddr *) &addr, (socklen_t *) &len);
        if(client < 0) {
            log_error("accept failed, errno: %d=%s", errno, strerror(errno));
            break;
        }
        log_info("SSL: Server accepted connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        if ((vpn->ssl_channel->ssl_handle = SSL_new(vpn->ssl_channel->ssl_context)) == NULL) {
            log_error("Failed to create SSL connection state object.");

        }

        SSL_set_fd(vpn->ssl_channel->ssl_handle, client);
        if (SSL_accept(vpn->ssl_channel->ssl_handle) == -1 ) {
            log_error("Failed SSL accept.");
            ERR_print_errors_fp(stderr);
        } else {
            vpn->vpn_state_callback(1337);
        }
    }
    ssl_disconnect(vpn->ssl_channel);
    return NULL;

}
/*
 * Initiate the SSL connection:
 * initiates the SSL_CHANNEL struct & binds it to the VPN,
 * initiates the SSL library, creates a SSL context and
 * calls all related set up functions.
 * Creates a TCP socket to the target server & binds the socket
 * to the created SSL context.
 */
int ssl_init(struct VPN *vpn) {

    log_info("Initiating SSL...");

    vpn->ssl_channel = malloc(sizeof(struct SSL_CHANNEL));


    if (vpn->ssl_channel == NULL) {
        log_error("malloc failed ssl init");
        return -1;
    }

    ssl_reset_stats(vpn->ssl_channel);

    if (SSL_library_init() < 0) {
        log_error("Could not initialize the OpenSSL library !");
        return -1;
    }

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();



    if (ssl_init_locking() < 0) {
        log_error("Could not initialize the locks!");
        return -1;
    }

    if (ssl_create_context(vpn->ssl_channel, vpn->server_mode) == -1) {
        log_error("Unable to create new SSL context.");
        return -1;
    }



    return 0;
}

int ssl_connect(struct VPN *vpn) {
    log_info("Initiating SSL connect...");

    if ((vpn->ssl_channel->ssl_handle = SSL_new(vpn->ssl_channel->ssl_context)) == NULL) {
        log_error("Failed to create SSL connection state object.");
        return -1;
    }

    if ((vpn->ssl_channel->ssl_socket = socket_connect(vpn->vpn_config)) < 0) {
        log_error("Failed to connect to %s:%d\n.", vpn->vpn_config->server_hostname, vpn->vpn_config->server_port);
        return -1;
    }

    if (!SSL_set_fd(vpn->ssl_channel->ssl_handle, vpn->ssl_channel->ssl_socket)) {
        log_error("Failed to associate ssl context with tcp socket.");
        return -1;
    }

    if (SSL_connect(vpn->ssl_channel->ssl_handle) != 1) {
        log_error("Error: Could not create an SSL session to: %s:%d.", vpn->vpn_config->server_hostname, vpn->vpn_config->server_port);
        return -1;
    }
    log_info("SSL connection established.");

    return 0;
}
/*
 * Attempts to disconnect the SSL connection.
 * The first disconnection attempt may fail,
 * and may therefore be attempted again.
 */
void ssl_disconnect(struct SSL_CHANNEL *ssl_channel) {

    local_persist int shutdown_attempts = 0;
    log_info("Terminating SSL/TLS connection...");


    if (!ssl_channel || !ssl_channel->ssl_handle) {
        return;
    }

    int shutdown = SSL_shutdown(ssl_channel->ssl_handle);

    log_info("SSL Shutdown status = %d", shutdown);

    if (shutdown == 0) {
        shutdown_attempts++;
        if (shutdown_attempts < 2) {
            ssl_disconnect(ssl_channel);
            return;
        }
    } else if (shutdown == 1) {

        ssl_cleanup_locking();

        SSL_free(ssl_channel->ssl_handle);
        SSL_CTX_free(ssl_channel->ssl_context);

        close(ssl_channel->ssl_socket);
        EVP_cleanup();
        ssl_channel->ssl_handle = NULL;
        ssl_channel->ssl_context = NULL;
        free(ssl_channel);
    } else {
        log_info("Shutdown returned unrecognized value: '%d'", shutdown);
    }

    log_info("Terminated SSL/TLS connection.");
}

private void ssl_reset_stats(struct SSL_CHANNEL *ssl_channel) {
    ssl_channel->ssl_stats.byte_count_in = 0;
    ssl_channel->ssl_stats.byte_count_out = 0;
}


//----------------------------------------------------------------------------------------
// SSL MULTI-THREAD SUPPORT
//----------------------------------------------------------------------------------------

global_variable pthread_mutex_t *mutex_buf = NULL;


/**
 * OpenSSL locking function.
 *
 * @param    mode    lock mode
 * @param    n        lock number
 * @param    file    source file name
 * @param    line    source file line number
 * @return    none
 */
private void ssl_locking_function(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&mutex_buf[n]);
    } else {
        pthread_mutex_unlock(&mutex_buf[n]);
    }
}

/**
 * OpenSSL uniq id function.
 *
 * @return    thread id
 */
private unsigned long ssl_id_function(void) {
    return ((unsigned long) pthread_self());
}


/**
 * OpenSSL allocate and initialize dynamic crypto lock.
 *
 * @param    file    source file name
 * @param    line    source file line number
 */
private struct CRYPTO_dynlock_value *ssl_dyn_create_function(const char *file, int line) {
    struct CRYPTO_dynlock_value *value;

    value = (struct CRYPTO_dynlock_value *)
            malloc(sizeof(struct CRYPTO_dynlock_value));
    if (!value) {
        goto err;
    }
    pthread_mutex_init(&value->mutex, NULL);

    return value;

    err:
    return (NULL);
}

/**
 * OpenSSL dynamic locking function.
 *
 * @param    mode    lock mode
 * @param    l        lock structure pointer
 * @param    file    source file name
 * @param    line    source file line number
 * @return    none
 */
private void ssl_dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l,
                                  const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&l->mutex);
    } else {
        pthread_mutex_unlock(&l->mutex);
    }
}

/**
 * OpenSSL destroy dynamic crypto lock.
 *
 * @param    l        lock structure pointer
 * @param    file    source file name
 * @param    line    source file line number
 * @return    none
 */
private void ssl_dyn_destroy_function(struct CRYPTO_dynlock_value *l,
                                     const char *file, int line) {
    pthread_mutex_destroy(&l->mutex);
    free(l);
}


private int ssl_init_locking(void) {
    int i;

    /* static locks area */
    mutex_buf = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    if (mutex_buf == NULL) {
        return (-1);
    }
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&mutex_buf[i], NULL);
    }
    /* static locks callbacks */
    CRYPTO_set_locking_callback(ssl_locking_function);
    CRYPTO_set_id_callback(ssl_id_function);


    /* dynamic locks callbacks, not sure if necessary! */

    CRYPTO_set_dynlock_create_callback(ssl_dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(ssl_dyn_lock_function);
    CRYPTO_set_dynlock_destroy_callback(ssl_dyn_destroy_function);

    RAND_load_file("/dev/urandom", 1024);

    return (0);
}

/**
 * Cleanup TLS library.
 *
 * @return    0
 */
private int ssl_cleanup_locking(void) {
    int i;

    if (mutex_buf == NULL) {
        return (0);
    }

    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);

    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);

    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&mutex_buf[i]);
    }
    free(mutex_buf);
    mutex_buf = NULL;

    return (0);
}


