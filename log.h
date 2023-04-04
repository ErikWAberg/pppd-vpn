#ifndef OSX_SSL_VPN_CLIENT_LOG_H
#define OSX_SSL_VPN_CLIENT_LOG_H

#include <stdint.h>
#include <stddef.h>

enum LOG_VERBOSITY {
    LOG_NONE = 0,
    LOG_INFO,
    LOG_TXRX,
    LOG_DATA
};


void log_init(enum LOG_VERBOSITY verbosity);

void log_info(const char *format, ...);

void log_txrx(const char *format, ...);

void log_error(const char *format, ...);

void log_data(const char *text, const uint8_t *data, size_t data_length);

#endif
