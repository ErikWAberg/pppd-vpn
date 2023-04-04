/*
 * log.c | log.h
 * The log-module
 *
 * Purpose:
 *
 *
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "log.h"
#include "definitions.h"


global_variable pthread_mutex_t mutex;
global_variable enum LOG_VERBOSITY log_verbosity = LOG_NONE;


void log_init(enum LOG_VERBOSITY verbosity) {
    log_verbosity = verbosity;
    pthread_mutex_init(&mutex, NULL);
    if(log_verbosity >= LOG_INFO) {
        log_info("LOG: Initiated with verbosity: %d", log_verbosity);
    }
}

void log_info(const char *format, ...) {
    if(log_verbosity >= LOG_INFO) {
        va_list args;

        pthread_mutex_lock(&mutex);
        printf("INFO: ");

        va_start(args, format);
        vprintf(format, args);
        va_end(args);

        printf("\n");

        fflush(stdout);

        pthread_mutex_unlock(&mutex);
    }
}

void log_txrx(const char *format, ...) {
    if(log_verbosity >= LOG_TXRX) {
        va_list args;

        pthread_mutex_lock(&mutex);
        printf("TXRX: ");

        va_start(args, format);
        vprintf(format, args);
        va_end(args);

        printf("\n");

        fflush(stdout);

        pthread_mutex_unlock(&mutex);
    }
}


void log_error(const char* format, ...) {
    va_list args;

    pthread_mutex_lock(&mutex);

    printf("ERRO: ");

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
    fflush(stdout);

    pthread_mutex_unlock(&mutex);

}

void log_data(const char* text, const uint8_t* data, size_t data_length) {
    if(log_verbosity >= LOG_DATA) {
        char *log_msg;
        int msg_pos = 0;

        log_msg = malloc(strlen(text) + data_length * 3 + 1 + ((data_length < 256) ? 16 : 0));

        if (log_msg == NULL) {
            //log error lol
            return;
        }

        strcpy(log_msg, text);
        msg_pos += strlen(log_msg);
        msg_pos += sprintf(&log_msg[msg_pos], "\n");

        if (data_length < 256) {
            msg_pos += sprintf(&log_msg[msg_pos], "Num bytes: 0x%02x\n", (unsigned int) data_length);
        }

        for (size_t i = 0; i < data_length; i++) {
            msg_pos += sprintf(&log_msg[msg_pos], "%02x%s", data[i], ((i + 1) % 16) ? "." : "\n");
        }

        sprintf(&log_msg[msg_pos - 1], "\n");

        puts(log_msg);

        free(log_msg);
    }
}



