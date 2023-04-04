#ifndef OSX_VPN_TCP_H
#define OSX_VPN_TCP_H

#include <arpa/inet.h>
#include <stdint.h>
#include "config.h"


int socket_connect(struct VPN_CONFIG* vpn_config);

int socket_open_listener(uint16_t port);

#endif
