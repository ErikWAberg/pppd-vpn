/*
 * hdlc.c | hdlc.h
 * The hdlc-module
 *
 * Purpose:
 * The hdlc-module is used to transform bytes
 * in or out of a hdlc-encoded format.
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "hdlc.h"
#include "definitions.h"
#include "log.h"


//8-bit asyncronous hdlc encoding

/*
*  FCS-16 table from
*  RFC 1662 HDLC-like Framing July 1994
*/

global_variable uint16_t fcstab[256] = {
        0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
        0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
        0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
        0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
        0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
        0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
        0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
        0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
        0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
        0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
        0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
        0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
        0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
        0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
        0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
        0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
        0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
        0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
        0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
        0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
        0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
        0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
        0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
        0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
        0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
        0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
        0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
        0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
        0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
        0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
        0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
        0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};



/*
* Calculate a new fcs given the current fcs and the new data.
* from RFC 1662 HDLC-like Framing July 1994.
 * This function is not used, but kept as a reference,
 * since the checksum operation below is performed in
 * the encoding/decoding functions.
*/
uint16_t pppfcs16(uint16_t fcs, uint8_t *cp, size_t len) {

    while (len--)
        fcs = (fcs >> 8) ^ fcstab[(fcs ^ *cp++) & 0xff];

    return (fcs);
}

#define INITIAL_FCS         0xffff // Initial FCS value
#define GOOD_FCS            0xf0b8 // Good final FCS value
#define PPP_PREFIX_CHECKSUM 0x3de3 // Pre-computed checksum of {0xff(Address), 0x03(Control)}
#define FCS_SIZE            2

// Significant octet values
#define HDLC_FLAG_SEQUENCE  0x7e   // Flag Sequence
#define HDLC_CONTROL_ESCAPE 0x7d   // Asynchronous Control Escape
#define HDLC_ESCAPE_BIT     0x20   // Asynchronous transparency modifier

#define PPP_ADDRESS         0xff   // PPP-Frames start with [0xff, 0x7d, 0x23]
#define PPP_CONTROL         0x23



//HDLC FlagSeq need only be prepended to the very first PPP-message
global_variable bool include_hdlc_flag_sequence = true;


private bool escape_needed(uint8_t octet) {
    if (octet < HDLC_ESCAPE_BIT || octet == HDLC_FLAG_SEQUENCE || octet == HDLC_CONTROL_ESCAPE) {
        return true;
    }
    return false;
}


/*
 * If the byte that is inserted into the frame is either:
 * - In the range [0, 0x20)
 * - Equal to 0x7e (Flag sequence character)
 * - Equal to 0x7d (Control escape character)
 *
 * then the special Control escape character is prepended to the array
 * to flag that the next byte has been XORed with the escape-bit character.
 */
private inline void hdlc_insert_octet(uint8_t octet, uint8_t* buffer, size_t* buffer_offset) {
    if (escape_needed(octet)) {
        buffer[(*buffer_offset)++] = HDLC_CONTROL_ESCAPE;
        buffer[(*buffer_offset)++] = octet ^ HDLC_ESCAPE_BIT;
    } else {
        buffer[(*buffer_offset)++] = octet;
    }

}

/*
 * Convert a PPP message into HDLC-like framing format.
 * The start and the end of a HDLC-frame is marked with
 * the Flag-sequence character.
 * However, since all messages end with the Flag-sequence,
 * only the very first frame that is sent to the pppd is
 * required to contain the Flag-sequence character.
 *
 * The checksum is is updated for each byte that is
 * converted and inserted into the HDLC-frame,
 * and then placed at the end of the HDLC-frame
 * (but before the Flag-sequence character).
 */
//TODO invalid frames handling, RFC 1662 HDLC-like Framing July 1994 4.3.  Invalid Frames
inline int hdlc_encode(uint8_t *ppp_frame, size_t ppp_frame_size, struct HDLC_DATA *hdlc_data) {

    uint16_t checksum = PPP_PREFIX_CHECKSUM;
    size_t octet_count = 0;

    if (include_hdlc_flag_sequence) {
        hdlc_data->hdlc_buffer[octet_count++] = HDLC_FLAG_SEQUENCE;
        include_hdlc_flag_sequence = false;
    }

    hdlc_insert_octet(PPP_ADDRESS, hdlc_data->hdlc_buffer, &octet_count);
    //Insert 0x03 -> inserts a Control-escaped value of 0x23=PPP_CONTROL
    hdlc_insert_octet(0x03, hdlc_data->hdlc_buffer, &octet_count);

    for (size_t i = 0; i < ppp_frame_size; i++) {
        checksum = (checksum >> 8) ^ fcstab[(checksum ^ ppp_frame[i]) & 0xff];
        hdlc_insert_octet(ppp_frame[i], hdlc_data->hdlc_buffer, &octet_count);
    }

    hdlc_insert_octet((checksum & 0xff) ^ 0xff, hdlc_data->hdlc_buffer, &octet_count);

    hdlc_insert_octet((checksum >> 8) ^ 0xff, hdlc_data->hdlc_buffer, &octet_count);

    hdlc_data->hdlc_buffer[octet_count++] = HDLC_FLAG_SEQUENCE;
    hdlc_data->hdlc_buffer_length = octet_count;

    return (int) octet_count;
}

/*
 * Locate the start and end of a HDLC-frame, marked by the Flag-sequence 0x7e.
 */
inline int hdlc_get_frame_offset(struct HDLC_DATA *hdlc_data, int *frame_start) {

    int start = -1, end = -1;

    for (int offset = *frame_start; offset < hdlc_data->hdlc_buffer_length; offset++) {
        if (hdlc_data->hdlc_buffer[offset] == HDLC_FLAG_SEQUENCE) {
            if (start == -1) {
                start = offset + 1;
            } else {
                end = offset;
                break;
            }

        }
    }

    if (start == -1 || end == -1) {
        return -1;
    }

    int frame_length = end - start;
    if (frame_length < 5) {
        *frame_start = end;
        return hdlc_get_frame_offset(hdlc_data, frame_start);
    }


    *frame_start = start;
    return frame_length;
}

/*
 * Decode a hdlc-encoded frame.
 */
inline int hdlc_decode(uint8_t *hdlc_frame, int hdlc_frame_length, uint8_t *decode_buffer, int buffer_size) {

    uint16_t checksum = INITIAL_FCS;
    size_t octet_count = 0;

    bool escaped = false;
    uint8_t octet = 0;

    int i = 0;

    if (hdlc_frame[0] == PPP_ADDRESS
        && hdlc_frame[1] == HDLC_CONTROL_ESCAPE
        && hdlc_frame[2] == PPP_CONTROL) {

        checksum = PPP_PREFIX_CHECKSUM;
        i = 3;

    }

    for (; i < hdlc_frame_length; i++) {
        octet = hdlc_frame[i];

        if (octet < HDLC_ESCAPE_BIT) {
            continue;   // Discard value
        }

        if (octet == HDLC_CONTROL_ESCAPE) {
            escaped = true;
            continue;
        } else if (escaped) {
            escaped = false;
            octet = octet ^ HDLC_ESCAPE_BIT;
        }

        if (octet_count >= buffer_size) {
            return ERR_HDLC_BUFF_SIZE;
        }

        decode_buffer[octet_count++] = octet;
        checksum = (checksum >> 8) ^ fcstab[(checksum ^ octet) & 0xff];
    }

    if (checksum != GOOD_FCS) {
        return ERR_HDLC_FCS;
    }

    octet_count -= FCS_SIZE;

    return octet_count;

}




