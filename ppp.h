#ifndef OSX_VPN_PPP_H
#define OSX_VPN_PPP_H

#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "vpn.h"

struct PPPD {
    pid_t pid;
    pid_t pty;
    struct in_addr ip_local;
    struct in_addr ip_remote;
    struct in_addr ip_dns1;
    struct in_addr ip_dns2;
};

struct PPP_PACKET {
    struct PPP_PACKET *next_packet;
    uint32_t num_bytes;
    uint8_t data[];
};

#define PPP_BUFFER_SIZE (2 * 4096)


#define PPP_HEADER_SIZE 8
#define PPP_MAGIC 0x12345678

struct VPN;

int ppp_init(struct VPN *vpn);
void *ppp_writer(void *arg);
void *ppp_reader(void *arg);

void ppp_insert_header(struct PPP_PACKET *ppp_packet);


#ifdef __APPLE__

#define PPP_INFO_SCRIPT "\
PATH=/usr/bin:/bin:/usr/sbin:/sbin\n\
if2service() {\n\
  local i\n\
  for i in $(echo \"list State:/Network/Service/[^/]+/PPP\" | scutil | cut -d/ -f4); do\n\
    if [[ \"$(echo show State:/Network/Service/$i/PPP | scutil | grep InterfaceName | cut -d' ' -f5)\" == ppp* ]]; then echo $i; return; fi\n\
  done\n\
}\n\
SERVICE=$(if2service $1) \n\
echo PPP Service: $SERVICE \n\
echo PPP State:\n\
echo show State:/Network/Service/$SERVICE/PPP | scutil \n\
echo IPv4 State:\n\
echo show State:/Network/Service/$SERVICE/IPv4 | scutil \n\
echo DNS State:\n\
echo show State:/Network/Service/$SERVICE/DNS | scutil \n\
echo Proxy State: \n\
scutil --proxy \n\
"
#endif

#endif
