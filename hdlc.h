#ifndef OSX_SSL_VPN_CLIENT_HDLC_CUSTOM_H
#define OSX_SSL_VPN_CLIENT_HDLC_CUSTOM_H

#include <sys/types.h>
#include <stdint.h>

#define ERR_HDLC_FCS        -1
#define ERR_HDLC_BUFF_SIZE  -2
#define ERR_HDLC_FRAME      -3

struct HDLC_DATA {
    uint8_t *hdlc_buffer;
    size_t hdlc_buffer_length;
};

int hdlc_encode(uint8_t* ppp_frame, size_t ppp_frame_size, struct HDLC_DATA* hdlc_data);
int hdlc_decode(uint8_t* hdlc_frame, int hdlc_frame_length, uint8_t* decode_buffer, int buffer_size);
int hdlc_get_frame_offset(struct HDLC_DATA *hdlc_data, int *frame_start);

#endif //OSX_SSL_VPN_CLIENT_HDLC_CUSTOM_H
