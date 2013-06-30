/*
**    u2_anon Process unified2 file and allow anonymization of different level of information 
**    (will create new file), simplifies the sharing of unified2 files.
**
**    Copyright (C) <2011> Eric Lauzon <beenph@gmail.com>
**
**    This program is free software: you can redistribute it and/or modify
**    it under the terms of the GNU General Public License as published by
**    the Free Software Foundation, either version 3 of the License, or
**    (at your option) any later version.
**
**    This program is distributed in the hope that it will be useful,
**    but WITHOUT ANY WARRANTY; without even the implied warranty of
**    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**    GNU General Public License for more details.
**
**    You should have received a copy of the GNU General Public License
**    along with this program.  If not, see <http://www.gnu.org/licenses/>.
**
**    u2_anon also uses code that is distributed with Snort (C) 2002-2011 Sourcefire,inc.
**
**
*/

#ifndef __U2_ANON_H__
#define __U2_ANON_H__

#include "decode.h"
#include "Unified2_common.h"

#define U2ANON_NAME "u2_anon"
#define U2ANON_MAJOR 0
#define U2ANON_MINOR 9
#define U2ANON_REVISION 1
#define U2ANON_BUILDREV 2


#define str(s) #s
#define xstr(s) str(s)

#define U2ANON_STRING xstr(U2ANON_NAME U2ANON_MAJOR.U2ANON_MINOR.U2ANON_REVISION rev U2ANON_BUILDREV)


#define ANON_STARTUP_ARG_COUNT 2 /* (input/output) */


/* NOTE: -elz Will need better def's of this */
#define DEBUG_LOW  1
#define DEBUG_MED  2
#define DEBUG_HIGH 3

/* NOTE: -elz This will be redone before official release */
#define ANON_EVENT      0x01
#define ANON_LINK_LAYER 0x02
#define ANON_PACKET     0x04
#define ANON_EXTRA_DATA 0x10


/* DLTMAX = DLT_IPV6 + 1 ) */
#define DLT_MAX DLT_IPV6 + 1

/* Default */
u_int8_t d_src_eth[6] = {0xAA,0xAA,0xAA,0xAA,0xAA,0xAA};
u_int8_t d_dst_eth[6] = {0xBB,0xBB,0xBB,0xBB,0xBB,0xBB}; 
/* Default */

/* Used for automatic decoder caller, like grinder for snort ...*/
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

    u_short v4_anonmask_enabled;
    u_short v6_anonmask_enabled;
    struct in_addr  v4_anonmask;
    struct in6_addr v6_anonmask;

    Packet pkt;


} u2AnonConfig;


#endif /* __U2_ANON_H__ */
