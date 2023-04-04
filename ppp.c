/*
 * ppp.c | ppp.h
 * The ppp-module
 *
 * Purpose:
 * Launch the Point-To-Point-daemon(pppd) program and connect it's
 * input/output descriptors to a pseudo-tty(pty), allowing us to read/write
 * data from/to the pppd process.
 *
 * The header file defines two structures:
 * PPPD -
 * Contains data related to the ppp-daemon such as it's associated pid and pty.
 *
 * PPP_PACKET -
 * Represents an individual PPP-packet, i.e. the actual bytes of the packet as
 * well as a count of the number of bytes that the packet contains.
 * It also has a pointer to the 'next packet' - which is used when storing a
 * set of PPP-packets in a queue.
 */


#include <termios.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include <stdbool.h>

#include "ppp.h"
#include "hdlc.h"
#include "log.h"
#include "definitions.h"

#ifdef __APPLE__

#include <util.h>

#else
#include <pty.h>
#include <sys/select.h>
#endif




private ssize_t ppp_write(pid_t pty, fd_set *write_fd, struct HDLC_DATA *hdlc_data);

private ssize_t ppp_read(pid_t pty, fd_set *read_fd, struct HDLC_DATA *hdlc_data);

private int ppp_decode(struct HDLC_DATA *hdlc_data, struct VPN *vpn);

private int ppp_extract_ip_dns(struct PPP_PACKET *ppp_packet, struct VPN* vpn);

private int ppp_extract_ip_remote(struct PPP_PACKET *ppp_packet, struct VPN* vpn);

/*
 * Insert magic number & package size into the header of
 * an outgoing PPP Packet.
 * The size of the header (PPP_HEADER_SIZE 8 bytes) should be excluded
 * when calculating the total package size.
 */
inline void ppp_insert_header(struct PPP_PACKET *ppp_packet) {
    ppp_packet->data[0] = 0x12;
    ppp_packet->data[1] = 0x34;
    ppp_packet->data[2] = 0x56;
    ppp_packet->data[3] = 0x78;
    ppp_packet->data[4] = (uint8_t) (ppp_packet->num_bytes >> 24);
    ppp_packet->data[5] = (uint8_t) (ppp_packet->num_bytes >> 16);
    ppp_packet->data[6] = (uint8_t) (ppp_packet->num_bytes >> 8);
    ppp_packet->data[7] = (uint8_t) (ppp_packet->num_bytes & 0xff);
}

/*
 * Forks and allocates a pseudo tty (pty) - the child process
 * launches an instance of the native ppp-daemon
 * which we achieve bi-directional communication with
 * through the pty.
 */
int ppp_init(struct VPN *vpn) {
    log_info("PPP: Initiating...");
    pid_t pid = 0;
    int amaster = 0;
    struct termios termp;

    termp.c_cflag = B115200 | CS8 | CLOCAL | CREAD;      /* Baud rate - set to anything != 0 */
    termp.c_iflag = 0;
    termp.c_oflag = 0;
    termp.c_lflag = 0;
    termp.c_cc[VMIN] = 1;
    termp.c_cc[VTIME] = 0;

    pid = forkpty(&amaster, NULL, &termp, NULL);

    if (pid == -1) {
        log_error("forkpty: %s\n", strerror(errno));
        return -1;
    } else if (pid == 0) {

        char *args[] = {
                "/usr/sbin/pppd",   //Path to ppp-daemon
                "default-asyncmap", //Force control characters to be escaped in both directions. We don't really want this...
                "noauth",           //Don't require server to authenticate itself
                "noipdefault",      //Disable automatic determination of local IP
                "noaccomp",         //Dont compress address in either send/recv direciton
                "nopcomp",          //Disable  protocol  field  compression negotiation.
                "receive-all",      //Accept all control characters  from  the  peer
                "nodetach",         //Don't allowd pppd to fork into background
                "novj",             //Disable Van Jacobson style TCP/IP header compression
                "local",            //Non-modem, ignore CD (Carrier Detect) signal from the modem
                "ipcp-max-configure", "50",
                //"mtu", "1400",
                //"mru", "1400",    //Max RX size

                //"kdebug", "1",
                //"kdebug", "7",    // Enable logging of input & output (7 gives max output)
                // Use the command
                // tail -f /var/log/system.log | grep --line-buffered ppp
                // in combination with kdebug >= 1 to read debug messages.

                NULL, NULL,
                NULL, NULL,
                NULL, NULL,
                NULL, NULL,
                NULL
        };

        int arg = 0;
        while (args[arg] != NULL) {
            arg++;
        }

        if(vpn->server_mode) {
            log_info("PPP: Running as server");
            args[arg++] = "silent";
            args[arg++] = "5.5.5.5:6.6.6.6";
            args[arg++] = "nodefaultroute";
            args[arg++] = "mru";
            args[arg++]=  "1467";
        } else if(vpn->client_mode) {
            log_info("PPP: Running as client");
            args[arg++] = "6.6.6.6:5.5.5.5";
            args[arg++] = "nodefaultroute";
            args[arg++] = "mru";
            args[arg++]=  "1467";
        } else  {
            args[arg++] = "usepeerdns";       //Ask the peer for up to 2 DNS server addresses.
            args[arg++] = "defaultroute"; //  //Do create default route to ppp interface

            if (strlen(vpn->vpn_config->user_name) > 0) {
                args[arg++] = "user";
                args[arg++] = vpn->vpn_config->user_name;
            }

            if (strlen(vpn->vpn_config->user_password) > 0) {
                args[arg++] = "password";
                args[arg++] = vpn->vpn_config->user_password;
            }
        }

        if (execvp(args[0], args) == -1) {
            log_error("execvp: %s", strerror(errno));
            return -1;
        }

    }

    int flags;
    if ((flags = fcntl(amaster, F_GETFL, 0)) == -1) {
        flags = 0;
    }

    flags = flags | O_RDWR | O_NOCTTY | O_NONBLOCK ;

    if (fcntl(amaster, F_SETFL, flags) == -1) {
        log_error("fcntl: %s", strerror(errno));
        return -1;
    }

    vpn->pppd->pid = pid;
    vpn->pppd->pty = amaster;

    return 0;
}


/*
 * Thread entry function.
 * Wait until packet from VPN server can be popped from the
 * ssl-to-pppd queue, perform HDLC-encoding on its contents
 * & write the resulting data to pppd via the pppd-pty.
 */
void *ppp_writer(void *arg) {

    struct VPN *vpn = (struct VPN *) arg;

    fd_set write_fd;
    FD_ZERO(&write_fd);
    FD_SET(vpn->pppd->pty, &write_fd);


    local_persist struct HDLC_DATA hdlc_data;
    local_persist uint8_t hdlc_buffer[4096];
    hdlc_data.hdlc_buffer = &hdlc_buffer[0];


    while (1) {

        hdlc_data.hdlc_buffer_length = 4096;
        ssize_t written = 0;

        struct PPP_PACKET *ppp_packet;
        ppp_packet = ppp_queue_pop(vpn->ssl_to_pppd_queue);

        if (!ppp_packet) {
            log_error("PPP-Writer: Received NULL package, terminating.");
            goto on_error_do_exit;
        }

        if(vpn->vpn_state == VPN_CONNECTING && ppp_packet->data[0] == 0x80) {
            //PPP packet starting with [0x80.0x21.0x02.x.y.z.0x03...] == accepted local ip + DNS(1&|2)

            if(     ppp_packet->data[1] == 0x21 &&
                    ppp_packet->data[2] == 0x02 &&
                    ppp_packet->data[6] == 0x03) {

                if(ppp_extract_ip_dns(ppp_packet, vpn) == 0) {
                    log_info("VPN IS CONNECTED");
                    vpn_set_state(vpn, VPN_CONNECTED);
                }

            }
        }

        written = (ssize_t) hdlc_encode(ppp_packet->data, ppp_packet->num_bytes, &hdlc_data);

        if (written == 0) {
            log_error("PPP-Writer: Failed to encode PPP packet, length = 0");
            break;
        } else if (written < 0) {
            log_error("PPP-Writer: Failed to encode PPP packet into HDLC frame.");
            goto on_error_do_exit;
        }

        written = ppp_write(vpn->pppd->pty, &write_fd, &hdlc_data);

        if (written == 0) {
            log_error("PPP-Writer: Wrote 0 to PPPD");
        } else if (written < 0) {
            log_error("PPP-Writer: Wrote < 0 to PPPD");
            goto on_error_do_exit;
        } else {
            log_data("PPP-Writer: ssl->pppd", hdlc_data.hdlc_buffer, (size_t) hdlc_data.hdlc_buffer_length);
        }

        free(ppp_packet);

        continue;

        on_error_do_exit:

        if (ppp_packet) {
            free(ppp_packet);
        }
        break;
    }

    log_error("PPP-Writer: Signaling termination");
    sem_post(&vpn->sem_terminate);
    return NULL;
}



/*
 * Thread entry function.
 * Wait until there is readable data on PPPD pty,
 * then HDLC-decode that data & make available to
 * send on SSL socket.
 * Since we don't know how much how many packets waiting to
 * be read, we store everything in a large buffer and then
 * parse it to find each individual package and then move the
 * tail of the buffer to the buffer head.
 */
void *ppp_reader(void *arg) {

    struct VPN *vpn = (struct VPN *) arg;
    fd_set read_fd;
    FD_ZERO(&read_fd);
    FD_SET(vpn->pppd->pty, &read_fd);

    struct HDLC_DATA hdlc_data;
    uint8_t data[PPP_BUFFER_SIZE];
    hdlc_data.hdlc_buffer_length = 0;
    hdlc_data.hdlc_buffer = &data[0];


    while (true) {

        ssize_t num_bytes_read;

        num_bytes_read = ppp_read(vpn->pppd->pty, &read_fd, &hdlc_data);

        if (num_bytes_read == -1) {
            if(errno == EAGAIN) continue;
            log_error("ppp-read: %s", strerror(errno));
            break;
        } else if (num_bytes_read == 0) {
            continue;
        }

        hdlc_data.hdlc_buffer_length += num_bytes_read;

        int buffer_offset = ppp_decode(&hdlc_data, vpn);

        if (buffer_offset < 0) {
            goto on_error_do_exit;
        }


        if (buffer_offset > 0 && buffer_offset < hdlc_data.hdlc_buffer_length) {
            memmove(hdlc_data.hdlc_buffer, &hdlc_data.hdlc_buffer[buffer_offset],
                    sizeof(*hdlc_data.hdlc_buffer) * (hdlc_data.hdlc_buffer_length - buffer_offset));
        }
        hdlc_data.hdlc_buffer_length = hdlc_data.hdlc_buffer_length - buffer_offset;

    }

    on_error_do_exit:

    log_error("PPP-Reader: Signaling termination");

    sem_post(&vpn->sem_terminate);

    return NULL;
}


/*
 * The hdlc_data struct contains x number of outgoing hdlc-encoded packets from the ppp
 * daemon. Thus, we first need to locate the start and end of each
 * packet and decode it. Once a packet has been decoded it is pushed onto
 * the pppd-to-ssl queue in order to be transmitted to the VPN server.
 */
private int ppp_decode(struct HDLC_DATA *hdlc_data, struct VPN *vpn) {

    int offset = 0;

    while (true) {

        int hdlc_frame_length = hdlc_get_frame_offset(hdlc_data, &offset);

        if (hdlc_frame_length == -1) {
            break;
        }

        struct PPP_PACKET *ppp_packet;

        ppp_packet = malloc(sizeof(*ppp_packet) + PPP_HEADER_SIZE + hdlc_frame_length);

        if (ppp_packet == NULL) {
            log_error("Malloc fail: ppp_packet in ppp_decode, size: %02x.", hdlc_frame_length);
            return ERR_ALLOC;
        }

        int decoded_size = hdlc_decode(&hdlc_data->hdlc_buffer[offset],
                                       hdlc_frame_length,
                                       &ppp_packet->data[PPP_HEADER_SIZE],
                                       hdlc_frame_length);

        if (decoded_size < 0) {
            free(ppp_packet);

            switch (decoded_size) {
                case ERR_HDLC_FCS:
                    log_error("HDLC_DECODE ERROR CHECKSUM");
                    break;
                case ERR_HDLC_BUFF_SIZE:
                    log_error("HDLC_DECODE ERROR BUFFSIZE");
                    break;
                case ERR_HDLC_FRAME:
                    log_error("HDLC_DECODE ERROR FRAME");
                    break;
                default:
                    log_error("HDLC_DECODE UNKNOWN ERROR: decoded size: %d \n", decoded_size);
                    break;
            }
            return decoded_size;
        }

        ppp_packet->num_bytes = (uint32_t) (decoded_size);
        offset += hdlc_frame_length + 1;

        if(vpn->vpn_state == VPN_CONNECTING && ppp_packet->data[0 + PPP_HEADER_SIZE] == 0x80) {
            //PPP packet starting with [0x80.0x21.0x02.x.y.z.0x03...] == accepted remote IP

            if(ppp_packet->data[1 + PPP_HEADER_SIZE] == 0x21 &&
                    ppp_packet->data[2 + PPP_HEADER_SIZE] == 0x02 &&
                    ppp_packet->data[6 + PPP_HEADER_SIZE] == 0x03) {

                if(ppp_packet->num_bytes == 12) {
                    ppp_extract_ip_remote(ppp_packet, vpn);
                }
            }
        }
        log_data("PPP READER: pppd->ssl", &ppp_packet->data[PPP_HEADER_SIZE],
                 (size_t) ppp_packet->num_bytes);

        ppp_queue_push(vpn->pppd_to_ssl_queue, ppp_packet);
    }

    return offset;
}


/*
 * Write the contents of the hdlc_data buffer to pppd via the pppd-pty.
 */
private ssize_t ppp_write(pid_t pty, fd_set *write_fd, struct HDLC_DATA *hdlc_data) {

    ssize_t written = 0, write_increment;
    int select_value = 0;

    while (written < hdlc_data->hdlc_buffer_length) {

        select_value = select(pty + 1, NULL, write_fd,
                              NULL, NULL);

        if (select_value == 0) {
            continue;
        } else if (select_value < 0) {
            return select_value;
        }


        write_increment = write(pty, &hdlc_data->hdlc_buffer[written],
                                (size_t) (hdlc_data->hdlc_buffer_length - written));

        if (write_increment < 0) {
            log_error("PPP_WRITE: write errno=%d:%s", errno, strerror(errno));
            return write_increment;
        }
        written += write_increment;
    }


    return written;
}

/*
 * Read as many available bytes as possible and can fit inside the buffer.
 */
private ssize_t ppp_read(pid_t pty, fd_set *read_fd, struct HDLC_DATA *hdlc_data) {

    int select_ret = select(pty + 1, read_fd, NULL, NULL, NULL);

    if (select_ret <= 0) {
        return select_ret;
    }

    return read(pty, &hdlc_data->hdlc_buffer[hdlc_data->hdlc_buffer_length],
                (size_t) (PPP_BUFFER_SIZE - hdlc_data->hdlc_buffer_length));

}

//  An example packet with the following contents:
// (in hex) 80.21.02.03.00.16.03.06.c0.a8.80.0a.81.06.0a.0a.0a.01.83.06.0a.06.00.14
// (in dec) 128.33.2.3.0.22.3.6.192.168.128.10.129.6.10.10.10.1.131.6.10.6.0.20
// yiels:
// Local ip:        192.168.128.10
// DNS 1(primary):  10.10.10.1
// DNS 2(second):   10.6.0.20
int ppp_extract_ip_dns(struct PPP_PACKET* ppp_packet, struct VPN* vpn) {

    char ip[16];
    int index = 0;

    if(ppp_packet->num_bytes > 12) {
        memcpy(&vpn->pppd->ip_local.s_addr, &ppp_packet->data[8], sizeof(uint8_t) * 4);
        for(int i = 0; i < 4; i++) {
            index += snprintf(&ip[index], 16, "%d.", ppp_packet->data[8 + i]);
        }
        ip[index - 1] = '\0';
        log_info("PPP: Received local IP: %s", ip);
    }

    if(ppp_packet->num_bytes >= 18) {
        memcpy(&vpn->pppd->ip_dns1, &ppp_packet->data[14], sizeof(uint8_t) * 4);
        index = 0;
        for(int i = 0; i < 4; i++) {
            index += snprintf(&ip[index], 16, "%d.", ppp_packet->data[14 + i]);
        }
        ip[index - 1] = '\0';
        log_info("PPP: Received Primary DNS: %s", ip);
    }

    if(ppp_packet->num_bytes >= 24) {
        memcpy(&vpn->pppd->ip_dns2, &ppp_packet->data[20], sizeof(uint8_t) * 4);
        index = 0;
        for(int i = 0; i < 4; i++) {
            index += snprintf(&ip[index], 16, "%d.", ppp_packet->data[20 + i]);
        }
        ip[index - 1] = '\0';
        log_info("PPP: Received Secondary DNS: %s", ip);
    }


    return 0;
}


int ppp_extract_ip_remote(struct PPP_PACKET* ppp_packet, struct VPN* vpn) {
    char ip[16];
    int index = 0;

    if(ppp_packet->num_bytes == 12) {
        memcpy(&vpn->pppd->ip_remote.s_addr, &ppp_packet->data[PPP_HEADER_SIZE + 8], sizeof(uint8_t) * 4);
        for (int i = 0; i < 4; i++) {
            index += snprintf(&ip[index], 16, "%d.", ppp_packet->data[PPP_HEADER_SIZE + 8 + i]);
        }
        ip[index - 1] = '\0';
        log_info("PPP: Received remote IP: %s", ip);
    }

    return 0;
}

