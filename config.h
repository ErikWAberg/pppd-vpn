#ifndef OSX_VPN_CONFIG_H
#define OSX_VPN_CONFIG_H

#include <arpa/inet.h>

#ifdef __APPLE__

#include <sys/types.h>

#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#define CONFIG_STR_LENGTH 64

struct VPN_CONFIG {
    char server_hostname[CONFIG_STR_LENGTH];
    uint16_t server_port;
    struct sockaddr_in server_sockaddr;
    char user_name[CONFIG_STR_LENGTH];
    char user_password[CONFIG_STR_LENGTH];
    char server_ssl_fingerprint[CONFIG_STR_LENGTH];
};

int config_read(struct VPN_CONFIG *vpn_config, const char *config_file);

#endif
