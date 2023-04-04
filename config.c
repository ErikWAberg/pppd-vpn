/*
 * config.c | config.h
 * The config-module
 *
 * Purpose:
 * Open a configuration file containing server information such as IP, port, as well
 * as the user-name of the vpn user. Performs simple string-compare parsing
 * of the file contents to locate the required key-value pairs:
 * Server IP Address, Server Port, Server SSL Fingerprint & Username.
 *
 */
#include <sys/types.h>
#include <netinet/in.h>
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <limits.h>
#include "config.h"
#include "definitions.h"
#include "log.h"



private int readFileData(const char *sFileName, char **sData, long *pnDataLen);

private int parse(char* file_data, struct VPN_CONFIG* vpn_config);

private char *getReadFileDataErrorDescription(int nError);


/*
 * Open a file and read all of its contents into a char array.
 * The char array is then parsed to extract configuration details.
 */
int config_read(struct VPN_CONFIG *vpn_config, const char *config_file) {

    char *file_data;
    long data_length;

    log_info("CONFIG: Parsing config file '%s'...", config_file);

    int nResult = readFileData(config_file, &file_data, &data_length);

    if (nResult != EXIT_SUCCESS) {
        log_error("CONFIG: Couldn't read file %s: (%s).\n", config_file,
                  getReadFileDataErrorDescription(nResult));
        return EXIT_FAILURE;
    } else {
        if(parse(file_data, vpn_config) != EXIT_SUCCESS) {
            return EXIT_FAILURE;
        }
        free(file_data);
    }

    log_info("CONFIG: Done parsing config file.");

    return EXIT_SUCCESS;
}

/*
 * The parse-function simply locates strings in the form of pairs of:
 * <key>value</key> - extracting the value in-between the key-tags
 * for each key contained in the search_keys array.
 * The set of search_keys should however probably be defined in
 * a more convenient manner.
 */
private int parse(char* file_data, struct VPN_CONFIG* vpn_config) {

    char *search_keys[] = {"User", "Server", "Port", "SSLFingerprint", NULL};

    char search_start_tag[CONFIG_STR_LENGTH];
    char search_end_tag[CONFIG_STR_LENGTH];
    char value[CONFIG_STR_LENGTH];
    int search_key_index = 0;

    while(search_keys[search_key_index] != NULL) {
        char* key = search_keys[search_key_index];
        char* start, *end;

        sprintf(search_start_tag, "<%s>", key);
        sprintf(search_end_tag, "</%s>", key);

        start = strstr(file_data, search_start_tag);
        end = strstr(file_data, search_end_tag);

        log_info("CONFIG: Searching for value of key: %s", key);

        if(start && end) {

            memcpy(value, start + strlen(search_start_tag), end - (start + strlen(search_start_tag)));

            value[end - (start + strlen(search_start_tag))] = '\0';

            if (strcmp(key, "User") == 0) {
                strcpy(vpn_config->user_name, value);
                log_info("CONFIG: Found value for key 'User=%s'", vpn_config->user_name);

            } else if (strcmp(key, "Server") == 0) {
                strcpy(vpn_config->server_hostname, value);
                //inet_aton(value, &vpn_config->server_address);
                log_info("CONFIG: Found value for key 'Server=%s'", vpn_config->server_hostname);

            } else if (strcmp(key, "Port") == 0) {
                vpn_config->server_port = 0;

                uintmax_t portConverted = strtoul(value, NULL, 10);

                if (portConverted == ULONG_MAX && errno == ERANGE) {
                    log_error("CONFIG: Could not convert value of 'Port' = '%s' to a valid number!");
                }

                vpn_config->server_port = (uint16_t) portConverted;
                log_info("CONFIG: Found value for key 'Port=%d'", (int) vpn_config->server_port);

            } else if (strcmp(key, "SSLFingerprint") == 0) {
                strcpy(vpn_config->server_ssl_fingerprint, value);
                log_info("CONFIG: Found value for key 'SSLFingerprint=%s'", vpn_config->server_ssl_fingerprint);
            }

        } else {
            log_error("CONFIG: Could not find value of key '%s'. Make sure XML file has proper tags etc.", key);
            return EXIT_FAILURE;
        }
        search_key_index++;
    }

    return EXIT_SUCCESS;
}

#define READ_FILE_NO_ERROR 0
#define READ_FILE_STAT_ERROR 1
#define READ_FILE_OPEN_ERROR 2
#define READ_FILE_OUT_OF_MEMORY 3
#define READ_FILE_READ_ERROR 4

/**
 * Returns an error description for a readFileData error code.
 *
 * @param nError the error code.
 * @return the error description.
 */
private char *getReadFileDataErrorDescription(int nError) {
    switch (nError) {
        case READ_FILE_NO_ERROR:
            return "no error";
        case READ_FILE_STAT_ERROR:
            return "no such file";
        case READ_FILE_OPEN_ERROR:
            return "couldn't open file";
        case READ_FILE_OUT_OF_MEMORY:
            return "out of memory";
        case READ_FILE_READ_ERROR:
            return "couldn't read file";
    }
    return "unknown error";
}

/**
 * Reads the complete contents of a file to a character array.
 *
 * @param sFileName the name of the file to read.
 * @param psData pointer to a character array that will be
 * allocated to read the file contents to.
 * @param pnDataLen pointer to a long that will hold the
 * number of bytes read to the character array.
 * @return 0 on success, > 0 if there was an error.
 * @see #getReadFileDataErrorDescription
 */
private int readFileData(const char *sFileName, char **psData, long *pnDataLen) {
    struct stat fstat;
    *psData = NULL;
    *pnDataLen = 0;
    if (stat(sFileName, &fstat) == -1) {
        return READ_FILE_STAT_ERROR;
    } else {
        FILE *file = fopen(sFileName, "r");
        if (file == NULL) {
            return READ_FILE_OPEN_ERROR;
        } else {
            *psData = malloc(fstat.st_size);
            if (*psData == NULL) {
                return READ_FILE_OUT_OF_MEMORY;
            } else {
                size_t len = fread(*psData, 1, fstat.st_size, file);
                fclose(file);
                if (len != fstat.st_size) {
                    free(*psData);
                    *psData = NULL;
                    return READ_FILE_READ_ERROR;
                }
                *pnDataLen = len;
                return READ_FILE_NO_ERROR;
            }
        }
    }
}




