/*
 *
 *
 *
 *
 *
 *
 */


#ifndef __U2_ANON_H__
#define __U2_ANON_H__

#include "decode.h"
#include "Unified2_common.h"

#define ANON_STARTUP_ARG_COUNT 2 /* (input/output) */

#define DEBUG_LOW  1
#define DEBUG_MED  2
#define DEBUG_HIGH 3

#define ANON_EVENT   0x01
#define ANON_PACKET  0x02
#define ANON_PAYLOAD 0x04


/* DLTMAX = DLT_IPV6 + 1 ) */
#define DLT_MAX DLT_IPV6 + 1

u_int8_t d_src_eth[6] = {0xAA,0xAA,0xAA,0xAA,0xAA,0xAA};
u_int8_t d_dst_eth[6] = {0xBB,0xBB,0xBB,0xBB,0xBB,0xBB}; 

/* Used for automatic decode caller. like grinder for snort ...*/
typedef struct _packetDecodeInstrumentation
{
    void (*decodePtr)(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
} packetDecodeInstrumentation;


#define EVENT_HEADER_STATE 0
#define UNIFIED2_EVENT_STATE 1

#define WRITE_BUFFER_DEFAULT_LENGTH  (IP_MAXPACKET + MAX_XFF_WRITE_BUF_LENGTH) /* Maximum u2 event size + max packet size */


typedef struct _u2AnonConfig
{
    /* input/output file descriptor */
    int inputfd;
    int outputfd;
    
    /* input/output directory descriptor */
    DIR *inputDirDesc;
    DIR *outputDirDesc;
    
    char *u2FilePrefix;
    
    char *inputFile;
    char *outputFile;
    char *inputDirectory;
    char *outputDirectory;
    
    
    u_int8_t batchProcess; /* Set if inputDirectory is set */
    u_int8_t process_flag;
    u_int8_t verbose_flag;

    
    char *write_buffer;
    ssize_t write_buffer_length; /* probably allow it to be set by user at some point... eg: min 1024 bytes.... should actually be min 1528(network mtu) + struct padding. */
    ssize_t last_read_length;
    
    struct stat inputStat;
    struct stat outputStat;

    Packet pkt;


} u2AnonConfig;



/* pseudo header for checksum calc */
/* Renamed to avoid define colision */
typedef struct __pseudoheader6
{
    uint32_t sip[4], dip[4];
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t len;
} csum_pheader6;

typedef struct __pseudoheader
{
    uint32_t sip, dip;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t len;
}csum_pheader;
 
/* pseudo header for checksum calc.*/


/* From snort util.h */
#define COPY4(x, y) \
    x[0] = y[0]; x[1] = y[1]; x[2] = y[2]; x[3] = y[3];

#define COPY16(x,y) \
    x[0] = y[0]; x[1] = y[1]; x[2] = y[2]; x[3] = y[3]; \
    x[4] = y[4]; x[5] = y[5]; x[6] = y[6]; x[7] = y[7]; \
    x[8] = y[8]; x[9] = y[9]; x[10] = y[10]; x[11] = y[11]; \
    x[12] = y[12]; x[13] = y[13]; x[14] = y[14]; x[15] = y[15];
/* From snort util.h */


#endif /* __U2_ANON_H__ */
