/*
 * socket.c | socket.h
 * The socket-module
 *
 * Purpose:
 * Create a POSIX-socket and connect it to a host using ip:port.
 */

#include <netdb.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <string.h>
#include "socket.h"
#include "log.h"
#include "definitions.h"

private int socket_resolve_server(char* hostname, uint16_t port, struct sockaddr_in* sockaddr);

int socket_connect(struct VPN_CONFIG* vpn_config) {
    log_info("Creating socket...");

    socket_resolve_server(vpn_config->server_hostname, vpn_config->server_port, &vpn_config->server_sockaddr);

    int socket_fd;

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        log_error("Could not create socket");
        return -1;
    }

    log_info("Connecting socket to %s:%d...",
             inet_ntoa(vpn_config->server_sockaddr.sin_addr), ntohs(vpn_config->server_sockaddr.sin_port));

    if (connect(socket_fd, (struct sockaddr *) &vpn_config->server_sockaddr, sizeof(struct sockaddr)) < 0) {
        log_error("Failed to connect socket, errno: %d=%s", errno, strerror(errno));
        return -1;
    }

    log_info("Connected to %s:%d", vpn_config->server_hostname, vpn_config->server_port);

    return socket_fd;
}


int socket_resolve_server(char* hostname, uint16_t port, struct sockaddr_in* sockaddr) {

    struct hostent *hp = gethostbyname(hostname);

    if (hp == NULL) {
        return 1;
    }


   // for(int i = 0; hp->h_addr_list[i] != NULL; i++) {
  //      if(hp->h_addrtype == AF_INET && hp->h_length == 4) {
    memset(sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_port = htons(port);
    sockaddr->sin_addr =  *( struct in_addr*) hp->h_addr;
   //     }
   // }

    return 0;
}


/*---------------------------------------------------------------------*/
/*--- OpenListener - create server socket                           ---*/
/*---------------------------------------------------------------------*/
int socket_open_listener(uint16_t port) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr *) &addr, sizeof(addr)) != 0 ) {
        log_error("Failed to bind port, errno: %d=%s", errno, strerror(errno));
        return -1;
    }

    if ( listen(sd, 10) != 0 ) {
        log_error("Can't configure listening port\", errno: %d=%s", errno, strerror(errno));
        return -1;
    }
    return sd;
}
