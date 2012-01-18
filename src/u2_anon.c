/*
*
*
*
*
*
*
*
*
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /* _GNU_SOURCE */


#include <dirent.h>
#include <fcntl.h>
#include <errno.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* 
#include <dnet.h>

Cause some include error because of some redefintions, since we
only need the two checksum function at the time of this writing we 
define them as extern and let the linker do its magic 
*/
extern void ip_checksum(void *buf, size_t len);
extern void ip6_checksum(void *buf, size_t len);

#include "sf_ip.h"
#include "sfbpf_dlt.h"
#include "u2_anon.h"

extern int errno;
extern char *optarg;
extern int optind, opterr, optopt;

static packetDecodeInstrumentation dInstr[DLT_MAX];
static u2AnonConfig *u2AnonContext;

void CleanExit(int exitVal)
{
    /* ADD CLEANUP CODE */
    if(u2AnonContext != NULL)
    {
	if(u2AnonContext->inputfd)
	{
	    close(u2AnonContext->inputfd);
	    u2AnonContext->inputfd = 0;
	}

	if(u2AnonContext->outputfd)
	{
	    close(u2AnonContext->outputfd);
	    u2AnonContext->outputfd = 0;
	}

	if(u2AnonContext->inputDirectory != NULL)
	{
	    free(u2AnonContext->inputDirectory);
	    u2AnonContext->inputDirectory = NULL;
	}
	
	if(u2AnonContext->outputDirectory != NULL)
	{
	    free(u2AnonContext->outputDirectory);
	    u2AnonContext->outputDirectory = NULL;
	}

	if(u2AnonContext->u2FilePrefix != NULL)
	{
	    free(u2AnonContext->u2FilePrefix);
	    u2AnonContext->u2FilePrefix = NULL;
	}

        if(u2AnonContext->inputFile != NULL)
	{
	    free(u2AnonContext->inputFile);
	    u2AnonContext->inputFile = NULL;
	}

	if(u2AnonContext->outputFile != NULL)
	{
	    free(u2AnonContext->outputFile);
	    u2AnonContext->outputFile = NULL;
	}

	if(u2AnonContext->write_buffer != NULL)
	{
	    free(u2AnonContext->write_buffer);
	    u2AnonContext->write_buffer = NULL;
	}
	
	free(u2AnonContext);
	u2AnonContext = NULL;
    }


    exit(exitVal);
}


void banner(int argc,char **argv)
{
    int x = 0;

    printf("----------------------------------------------\n"
	   "|        Unified2 Anonymizer                 |\n"
	   "|        Eric Lauzon <beenph@gmail.com> 2011 |\n"
	   "----------------------------------------------\n");
    
    if(argv != NULL)
    {
	printf("Unified2 Anonymizer Command line: ");
	
	for(x = 0; x < argc ; x++)
	{
	    printf(" %s ",argv[x]);
	}
	
	printf("\n");
    }
    
    return;
}


/*
 *
 *
 *
 */
void usage(void)
{

    printf("\n\n"
	   "----------------------------------------------\n"	   
	   "|       Unified2 Anonymizer usage()          |\n"
	   "----------------------------------------------\n"	   
	   "| -r:  \t[Unified2 Input file (single)]\n"
	   "| -o:  \t[Unified2 Output File (single)]\n"
	   "| -R:  \t[Unified2 Input Directory]\n"
	   "| -O:  \t[Unified2 Output Directory]\n"
	   "| -s:  \t[Unified2 File Prefix]\n"
	   "| -L: \t[Unified2 Packet Layer type]\n"
	   "| -dD: \t[Anonymize Data(Payload)]\n"
	   "| -eE: \t[Anonymize Event]\n"
	   "| -pP: \t[Anonymize Payload]\n"
	   "| -v:  \t[Verbose flag]\n"
	   "| -h:  \t[Show Usage]\n"
	   "----------------------------------------------\n"
	   "----------------------------------------------\n\n");
	return;
}

/*
**
**
**
**
**
*/
void printContext(u2AnonConfig *iConfig)
{
    if(iConfig == NULL)
    {
	/* XXX */
	return;
    }
    
    printf("----------------------------------------------\n"
	   "| Unified2 Invocation arguments\n"
	   "|\n");
    
    if(iConfig->inputFile != NULL)
    {
	printf("| Input File : [%s]\n",
	       iConfig->inputFile);
    }
    if(iConfig->inputDirectory != NULL)
    {
	printf("| Input Directory [%s]\n",
	       iConfig->inputDirectory);
    }
    if(iConfig->outputFile != NULL)
    {
	printf("| Output File [%s]\n",
	       iConfig->outputFile);
    }
    
    if(iConfig->outputDirectory != NULL)
    {
	printf("| Output Directory [%s]\n",
	       iConfig->outputDirectory);
    }
    
    if(iConfig->u2FilePrefix != NULL)
    {
	printf("| Unified2 File Prefix [%s]\n",
	       iConfig->u2FilePrefix);
    }
    
    printf("| Anonymize Event [%u]\n"
	   "| Anonymize Payload [%u]\n"
	   "| Anonymize Packet [%u]\n"
	   "----------------------------------------------\n\n",
	   iConfig->verbose_flag & ANON_EVENT ,
	   iConfig->verbose_flag & ANON_PAYLOAD,
	   iConfig->verbose_flag & ANON_PACKET);
    
    return;
}


/*
**
**
**
**
*/
int validateCmdLine(u2AnonConfig *iConf)
{

    DIR *oDir = NULL;
    int fd = 0;

    if(iConf == NULL)
    {
	/* XXX */
	return 1;
    }

    /* ERROR */
    if(iConf->process_flag == 0)
    {
	printf("ERROR: [%s()],no anonymized switch has been used, please select one \n",
	       __FUNCTION__);
	return 1;
    }

    if( (iConf->inputFile == NULL) &&
	(iConf->inputDirectory == NULL) &&
	(iConf->outputFile == NULL) &&
	(iConf->outputDirectory == NULL))
    {
	printf("ERROR: [%s()],need at least an input file or directory and an output file or directory to process something.\n\n",
	       __FUNCTION__);
	return 1;
    }
	
    
    if( (iConf->inputFile != NULL) &&
	(iConf->inputDirectory != NULL))
    {
	printf("ERROR: [%s()],can't process an input file and an input directory, specifty only one processing argument \n\n",
	       __FUNCTION__);
	return 1;
    }
    
    
    if( ((iConf->inputFile != NULL) &&
	 (iConf->outputDirectory == NULL && iConf->outputFile == NULL)))
    {
	printf("ERROR: [%s()],a input file was specified but no output directory or output file was specified. \n\n",
	       __FUNCTION__);
	return 1;
    }
    
    if( (iConf->inputDirectory != NULL) &&
	(iConf->outputDirectory == NULL))
    {
	printf("ERROR: [%s()],an input directory was specified but no output directory was specified, please define an output direcyory \n\n",
	       __FUNCTION__);
	return 1;
    }
    /* ERROR */
    
    /* WARNING */
    if( (iConf->inputDirectory != NULL) &&
	(iConf->u2FilePrefix == NULL))
    {
	printf("WARNING: [%s()],an input directory was specified but not unified2 file prefix was specified, every file in the directory [%s] will be processed \n\n",
	       __FUNCTION__,
	       iConf->inputDirectory);
    }
    
    
    if( (iConf->inputFile != NULL) &&
	(iConf->u2FilePrefix != NULL))
    {
	printf("WARNING: [%s()],a input file was specified [%s] and a unified2 file prefix was specified [%s] , input file will superseed the uses of unified2 file prefix \n\n",
	       __FUNCTION__,
	       iConf->inputFile,
	       iConf->u2FilePrefix);
	
    }
    /* WARNING */
    
    /* Validate arguments */
    if(iConf->inputDirectory != NULL)
    {
	if( (oDir=opendir(iConf->inputDirectory)) == NULL)
	{
	    /* XXX */
	    perror("opendir()");
	    return 1;
	}
	
	closedir(oDir);
	oDir = NULL;
    }
    
    if(iConf->outputDirectory != NULL)
    {
	if( (oDir=opendir(iConf->outputDirectory)) == NULL)
        {
            /* XXX */
            perror("opendir()");
            return 1;
        }
	
        closedir(oDir);
        oDir = NULL;
    }
    
    if(iConf->inputFile != NULL)
    {
	if( (fd = open(iConf->inputFile,O_RDONLY)) < 0)
        {
            perror("open()");
            return 1;
        }
	
        close(fd);
    }
    
    if(iConf->outputFile != NULL)
    {
	if( stat(iConf->outputFile,&iConf->outputStat) < 0)
	{
	    if(errno != ENOENT)
	    {
		perror("stat()");
		return 1;
	    }
	}
	else
	{
	    printf("ERROR: [%s()]: File [%s] exist, will not overwrite \n",
		   __FUNCTION__,
		   iConf->outputFile);
	    return 1;
	}
    }
    
    return 0;

}

/*
 *
 *
 *
 *
 */
u2AnonConfig * parseCommandLine(int argc,char **argv)
{
    u2AnonConfig *rConfig = NULL;
    
    int cOpt = 0;
    
    u_int32_t add_leading_slash = 0;
    u_int32_t pathlen = 0;
    
    
    if( (argc < ANON_STARTUP_ARG_COUNT) ||
	(*argv == NULL))
    {
        /* XXX */
	usage();
	return NULL;
    }
    
    if( (rConfig=(u2AnonConfig *)calloc(1,sizeof(u2AnonConfig))) == NULL)
    {
	/* XXX */
	return NULL;
    }
    

    while( (cOpt = getopt(argc,argv,"r:R:o:O:s:L:DdEehPpv")) != -1)
    {

	add_leading_slash = 0;
	pathlen = 0;

	switch(cOpt)
	{
	    
	case 'L':
	    if(optarg != NULL)
	    {
		
		printf("do something \n");	


	    }
            else
            {
		goto f_err;
	    }
	    break;

	case 's':
            if(optarg != NULL)
            {
                if( (rConfig->u2FilePrefix = strndup(optarg,(strlen(optarg)+1))) == NULL)
                {
                    goto f_err;
                }
            }
	    else
	    {
                goto f_err;
            }
	    break;
	    
	case 'r':
	    if(optarg != NULL)
	    {
		if( (rConfig->inputFile = strndup(optarg,(strlen(optarg)+1))) == NULL)
		{
		    goto f_err;		
		}
	    }
	    else
	    {
		
		goto f_err;		
	    }


	    break;
	    
	case 'R':
	    if(optarg != NULL)
	    {
		pathlen = strlen(optarg);
		
		if(optarg[pathlen] != '/')
		{
		    pathlen += 1;
		    add_leading_slash = 1;
		}
		
		if( (rConfig->inputDirectory = strndup(optarg,pathlen+1)) == NULL)
		{
		    goto f_err;		
		}
		
		if(add_leading_slash)
		{
		    rConfig->inputDirectory[pathlen-1] = '/';
		}

		/* We will be processing a directory */
		rConfig->batchProcess = 1;

	    }
	    else
	    {
		goto f_err;		
	    }
	    break;
	    
	case 'o':
	    if(optarg != NULL)
	    {
		if( (rConfig->outputFile = strndup(optarg,strlen(optarg)+1)) == NULL)
		{
		    goto f_err;		
		}
	    }
	    else
	    {
		goto f_err;		
	    }
	    break;
	    
	case 'O':
	    if(optarg != NULL)
	    {
		pathlen = strlen(optarg);
		
                if(optarg[pathlen] != '/')
                {
                    pathlen += 1;
                    add_leading_slash = 1;
                }

		if( (rConfig->outputDirectory = strndup(optarg,pathlen+1)) == NULL)
		{
		    goto f_err;		
		}
		
		if(add_leading_slash)
                {
                    rConfig->outputDirectory[pathlen-1] = '/';
                }
	    }
	    else
	    {
		goto f_err;		
	    }
	    break;
	    
	case 'E':
	case 'e':
	    rConfig->process_flag ^= (ANON_EVENT);
	    break;
	    
	case 'D':
	case 'd':
	    rConfig->process_flag ^= (ANON_PAYLOAD);
	    break;
	    
	case 'P':
	case 'p':
	    rConfig->process_flag ^= (ANON_PACKET);
	    break;
	    
	case 'H':
	case 'h':
	    usage();
	    
	    if(rConfig != NULL)
	    {
		free(rConfig);
		rConfig = NULL;
	    }
	    CleanExit(0);
	    break;
	    
	case 'v':
	    rConfig->verbose_flag++;
	    break;
	    
	default:
	    printf("[%s()]: Unknown option specified [%c][0x%x], bailing.... \n",
		   __FUNCTION__,
		   cOpt,
		   cOpt);
	
	goto f_err;
	break;
	
	}
    }
    
    if( (validateCmdLine(rConfig)))
    {
	goto ex_err;
    }
    
    return rConfig;
    
f_err:

    printf("[%s()]: option [%c], ERROR processing option \n",
	   __FUNCTION__,
	   cOpt);
ex_err:
    if(rConfig != NULL)
    {
	free(rConfig);
	rConfig = NULL;
    }
    
    usage();
    return NULL;
}


void sigHand(int sig)
{
    printf("Parent PID [%u] Process PID [%u], received signal [%d], cleaning up and exiting \n",
	   getppid(),
	   getpid(),
	   sig);
    
    /* Do not call clean exit on sigsegv... */
    if(sig != 11)
	CleanExit(1);
}

void setupSignal(void)
{
    int x = 0;
    struct sigaction SigStr;
    struct sigaction oldSigStr;

    memset(&SigStr,'\0',sizeof(struct sigaction));
    memset(&oldSigStr,'\0',sizeof(struct sigaction));
    
    /* setup signal handlers */    
    SigStr.sa_handler = &sigHand;
    
    for(x = 1; x <= 31; x++)
    {
	/* Ignore sighand for SIGKILL and SIGSTOP */
	if( (x != 9)  &&
	    (x != 17) &&
	    (x != 19) &&
	    (x != 23))
	{
	    if( (sigaction(x,&SigStr,&oldSigStr)))
		
	    {
		/* XXX */
		CleanExit(1);
	    }
	}
    }
}    



u_int32_t u2WriteData(int fd,void *buf,ssize_t wlen)
{
    if( write(fd,buf,wlen) < 0 )
    {
	/* XXX */
	perror("write()");
	return 1;
    }
    return 0;
}


/* ANON FUNCTIONS */
u_int32_t u2Anon_UNIFIED2_IDS_EVENT(char *dptr,u_int32_t length,u_int8_t anon_level)
{
    
    Unified2IDSEvent *cEvent = NULL;
    
    if((dptr == NULL) ||
       (length == 0))
    {
	/* XXX */
	return 1;
    }
    
    cEvent=(Unified2IDSEvent *)dptr;
    
    if(anon_level & ANON_EVENT)
    {
	cEvent->ip_source=htonl(INADDR_LOOPBACK);
	cEvent->ip_destination=htonl(INADDR_LOOPBACK);
    }
    else if(anon_level & ANON_PAYLOAD)
    {
	memset(cEvent,'\0',sizeof(Unified2IDSEvent));
	cEvent->ip_source=htonl(INADDR_LOOPBACK);
	cEvent->ip_destination=htonl(INADDR_LOOPBACK);
    }
    

    return 0;
}

u_int32_t u2Anon_UNIFIED2_IDS_EVENT_IPV6(char *dptr,u_int32_t length,u_int8_t anon_level)
{

    Unified2IDSEventIPv6 *cEvent = NULL;

    if((dptr == NULL) ||
       (length == 0))
    {
	/* XXX */
	return 1;
    }

    cEvent = (Unified2IDSEventIPv6 *)dptr;
    
    if(anon_level & ANON_EVENT)
    {
	cEvent->ip_source.s6_addr32[2] = 0xffff0000;
	cEvent->ip_source.s6_addr32[3] = htonl(INADDR_LOOPBACK);
	
	cEvent->ip_destination.s6_addr32[2] = 0xffff0000;
	cEvent->ip_destination.s6_addr32[3] = htonl(INADDR_LOOPBACK);
    }
    else if(anon_level & ANON_PAYLOAD)
    {
	memset(cEvent,'\0',sizeof(Unified2IDSEventIPv6));
	
	cEvent->ip_source.s6_addr32[2] = 0xffff0000;
	cEvent->ip_source.s6_addr32[3] = htonl(INADDR_LOOPBACK);
	
	cEvent->ip_destination.s6_addr32[2] = 0xffff0000;
	cEvent->ip_destination.s6_addr32[3] = htonl(INADDR_LOOPBACK);
    }
    
    return 0;
}

u_int32_t Checksum(Packet *iPkt,u_int32_t pktlen)
{
    if( (iPkt == NULL) ||
	pktlen == 0)
    {
	/* XXX */
	return 1;
    }
    
    if(iPkt->iph)
    {

	if(IS_IP4(iPkt))
	{
	    ip_checksum((void *)iPkt->iph,
			(pktlen - ((void *) iPkt->iph - (void *)iPkt->pkt)));
	}
	else if(IS_IP6(iPkt))
	{
	    ip6_checksum((void *)iPkt->iph,
			 (pktlen - ((void *) iPkt->iph - (void *)iPkt->pkt)));
	}
	else
	{
	    goto cksum_err;
	}
    }
    
    return 0;
    
cksum_err:
    printf("[%s()]: Encountered an error while running checksum against a packet \n",
	   __FUNCTION__);
    return 1;
}


u_int32_t u2Anon_UNIFIED2_PACKET(char *dptr,u_int32_t length,u_int8_t anon_level)
{
    DAQ_PktHdr_t fDAQPktHdr;
    Packet tPkt = {0};
    Serial_Unified2Packet *cPkt = NULL;

    u_int32_t link_layer_type = 0;

    struct in_addr v4addr = {0};
    sfip_t v6addr;

    u_int32_t payload_length = 0;

    char *wPtr = NULL;

    if((dptr == NULL) ||
       (length == 0))
    {
	/* XXX */
	return 1;
    }

    memset(&fDAQPktHdr,'\0',sizeof(DAQ_PktHdr_t));
    
    /* NOTE: -elz
       At one point people are probably gonna be 
       able to provide "rules" to mask certain net etc..
       but for now we go straight to the point 
       and set it to loopback 
    */
    v4addr.s_addr = htonl(INADDR_LOOPBACK);

    memset(&v6addr,'\0',sizeof(sfip_t));
    v6addr.ip.u6_addr32[2] = 0xffff0000;
    v6addr.ip.u6_addr32[3] = htonl(INADDR_LOOPBACK);
    
    cPkt = (Serial_Unified2Packet *)dptr;
    
    link_layer_type = ntohl(cPkt->linktype);
    
    fDAQPktHdr.caplen = ntohl(cPkt->packet_length);
    fDAQPktHdr.pktlen = ntohl(cPkt->packet_length);
    
    
    if(dInstr[link_layer_type].decodePtr != NULL)
    {
	/* NOTE: -elz 
	   it would be nice to know about decoding errors...mabey we could
	   enchance decode's function a bit for our context so we do not get
	   bad surprise down the line ...
	*/
	dInstr[link_layer_type].decodePtr(&tPkt,&fDAQPktHdr,cPkt->packet_data);
    }
    else
    {
	printf("ERROR: [%s()]: Can't decode Link layer type [%u] , comming from packet event \n",
	       __FUNCTION__,
	       link_layer_type);
	return 1;
    }


    if(tPkt.eh)
    {
	memcpy(&tPkt.eh->ether_dst,&d_src_eth,(sizeof(u_int8_t) * 6));
	memcpy(&tPkt.eh->ether_src,&d_dst_eth,(sizeof(u_int8_t) * 6));
    }

    
    /* check anon level ...etc */
    /* We check if we have a portscan first... */
    if(( ((tPkt.iph == NULL) && (tPkt.inner_iph != NULL)) &&
	 ((tPkt.ip4h == NULL)) && (tPkt.inner_iph != NULL)))
    {
	if(tPkt.inner_iph->ip_proto == 255)
	{
	    memcpy((struct in_addr *)&tPkt.inner_iph->ip_src,&v4addr,sizeof(struct in_addr));
	    memcpy((struct in_addr *)&tPkt.inner_iph->ip_dst,&v4addr,sizeof(struct in_addr));
	    
	    
	    payload_length = fDAQPktHdr.caplen - ((char *)tPkt.inner_iph - (char *)tPkt.pkt);
	    wPtr =(char *)(tPkt.inner_iph);
	    memset(wPtr,'\0',(sizeof(char) * payload_length));
	    return 0;
	}
    }
    
    
    if(tPkt.ip4h != NULL)
    {
	memcpy((struct sfip_t *)&tPkt.ip4h->ip_src,&v6addr,sizeof(sfip_t));
	memcpy((struct sfip_t *)&tPkt.ip4h->ip_dst,&v6addr,sizeof(sfip_t));

    }

    if(tPkt.ip6h != NULL)
    {
	memcpy((struct sfip_t *)&tPkt.ip6h->ip_src,&v6addr,sizeof(sfip_t));
	memcpy((struct sfip_t *)&tPkt.ip6h->ip_dst,&v6addr,sizeof(sfip_t));
    }
    
    if(tPkt.iph != NULL)
    {
	memcpy((struct in_addr *)&tPkt.iph->ip_src,&v4addr,sizeof(struct in_addr));
	memcpy((struct in_addr *)&tPkt.iph->ip_dst,&v4addr,sizeof(struct in_addr));
    }
    
    
    if( (tPkt.data != NULL) && 
	(tPkt.pkt != NULL))
    {
	if( (payload_length =  fDAQPktHdr.caplen - (tPkt.data - tPkt.pkt)) > 0)
	{
	    wPtr = (char *)tPkt.data;
	    memset(wPtr,'\0',payload_length);
	}
    
    
	/* Re-generate checksum for the packet */
	if( (Checksum(&tPkt,fDAQPktHdr.pktlen)))
	{
	    /* XXX */
	    return 1;
	}
    }
    
    return 0;
}
/* ANON FUNCTIONS */



/*
**
**
**
**
*/
u_int32_t u2Anonymize(char *dptr,u_int32_t event_type,u_int32_t length,u_int8_t anon_level)
{
    if(dptr == NULL)
    {
	/* XXX */
	return 1;
    }
    
    switch(event_type)
    {
	
    case UNIFIED2_PACKET:
	return u2Anon_UNIFIED2_PACKET(dptr,length,anon_level);
	break;
	
    case UNIFIED2_IDS_EVENT:
    case UNIFIED2_IDS_EVENT_VLAN:
    case UNIFIED2_IDS_EVENT_MPLS:
    case UNIFIED2_IDS_EVENT_NG:
	/* Since sturcture follow almost the same maping we apply 
	   a higher level of anonymity for events, 
	   we could if needed for NG elements, actually plug its own function 
	   (and the same could go if we would like to anon other sub specific fields..)
	*/
	return u2Anon_UNIFIED2_IDS_EVENT(dptr,length,anon_level);
	break;
	
    case UNIFIED2_IDS_EVENT_IPV6_MPLS:
    case UNIFIED2_IDS_EVENT_IPV6:
    case UNIFIED2_IDS_EVENT_IPV6_VLAN:
    case UNIFIED2_IDS_EVENT_IPV6_NG:
	/* Since sturcture follow almost the same maping we apply 
	   a higher level of anonymity for events, 
	   we could if needed for NG elements, actually plug its own function 
	   (and the same could go if we would like to anon other sub specific fields..)
	*/
	return u2Anon_UNIFIED2_IDS_EVENT_IPV6(dptr,length,anon_level);
	break;
	
    case UNIFIED2_EXTRA_DATA:
	return 0; /* for now */
	break;
	
    default:
	/* XXX */
	printf("ERROR: [%s()]: Unknown event type [%u] \n",
	       __FUNCTION__,
	       event_type);
	return 1;
	break;
	
    }
    
    return 0;
}
	
/* 
 *  If we encounter a partial event read , 
 *  we set rem_length
 */
u_int32_t u2ProcessBuffer(u2AnonConfig * iConf,ssize_t read_size,ssize_t *rem_length)
{
    Serial_Unified2_Header *event_header = NULL;    
    Serial_Unified2IDSEvent_legacy *leg_ass = NULL;
    Serial_Unified2Packet *pkt_ass = NULL;
    
    char *cbuf = NULL;
    char *tbuf = NULL;
    ssize_t buf_pos = 0;
    
    u_int32_t processing_state = 0;

    ssize_t clen;
    ssize_t leftover = 0;
    
    if( (iConf == NULL) ||
	(rem_length == NULL) ||
	(read_size == 0))
    {
	/* XXX */
	return 1;
    }
    
    cbuf = (char *)iConf->write_buffer;
    
    while(buf_pos <= read_size)
    {
	switch(processing_state)
	{
	case EVENT_HEADER_STATE:
	    
	    event_header =(Serial_Unified2_Header *)(cbuf+buf_pos);
	    
	    if((buf_pos + sizeof(Serial_Unified2_Header) + ntohl(event_header->length)) >  read_size)
	    {
		leftover = read_size - buf_pos;
		goto set_bytes;
	    }
	    
	    buf_pos += sizeof(Serial_Unified2_Header);
	    processing_state = UNIFIED2_EVENT_STATE;
	    
	    if( u2WriteData(iConf->outputfd,event_header,sizeof(Serial_Unified2_Header)))
	    {
		/* XXX */
		return 1;
	    }
	    break;
	    
	case UNIFIED2_EVENT_STATE:
	    
	    /* DEBUG */
	    // printf("Got an event of type [%u] of length [%u] \n",
	    // ntohl(event_header->type),
	    // ntohl(event_header->length));
	    
	    // printf("read_size [%u] buf_pos [%u] event len [%u] \n",
	    // read_size,
	    // buf_pos,
	    // ntohl(event_header->length));
	    /* DEBUG */
	    
	    tbuf = (cbuf + buf_pos);
	    clen = ntohl(event_header->length);
	    buf_pos += clen;
	    
	    if(u2Anonymize(tbuf,
			   ntohl(event_header->type),
			   clen,
		           iConf->process_flag))
	    {
		/* XXX */
		return 1;
	    }
	    
	    if( u2WriteData(iConf->outputfd,tbuf, clen))
	    {
		/* XXX */
		return 1;
	    }	  
	    
	    processing_state = EVENT_HEADER_STATE;
	    
	    if( (buf_pos + sizeof(Serial_Unified2_Header)) > read_size)
	    {
		leftover = read_size - buf_pos;
		goto set_bytes;
	    }

	    break;
	    
	}
	
    }
    
    return 0;
    
set_bytes:
    *rem_length = leftover;
    return 0;
}


/*
**
** This function might look ackward but we read the largest chunk possible, then 
** work with the buffer, process an event, write the event  until we can't process our buffer.
** avoid 1 to 1 read / write.
** 
**
*/
u_int32_t u2ProcessLoop(u2AnonConfig *iConf)
{
    ssize_t current_offset = 0;
    ssize_t read_offset = 0;
    ssize_t read_size = 0;
    ssize_t rem_length = 0;
    
    if(iConf == NULL)
    {
	/* XXX */
	return 1;
    }
    
    if(iConf->write_buffer_length > iConf->inputStat.st_size)
    {
        read_offset = iConf->inputStat.st_size;
    }
    else
    {
        read_offset = iConf->write_buffer_length;
    }
    
    while(current_offset < iConf->inputStat.st_size)
    {
        if( (current_offset + read_offset) > iConf->inputStat.st_size)
        {
            read_offset = iConf->inputStat.st_size - current_offset;
        }
	
	memset(iConf->write_buffer,'\0',iConf->write_buffer_length);
	
	if( (read_size = read(iConf->inputfd,iConf->write_buffer,read_offset)) < 0)
	{
	    perror("read()");
	    return 1;
	}
	
	current_offset += read_size;	    
	
	if( (u2ProcessBuffer(iConf,read_size,&rem_length)))
	{
	    /* XXX */
	    return 1;
	}
	
	if(rem_length != 0)
	{
	    current_offset -= rem_length;
	    
	    if( lseek(iConf->inputfd,current_offset,SEEK_SET) < 0)
	    {
		/* XXX */
		perror("lseek()");
		return 1;
	    }
	}
    }
    
    return 0;
}


u_int32_t u2WriteTest(u2AnonConfig *iConf,char *inputFile,char *outputFile)
{
    ssize_t write_offset = 0;
    ssize_t current_offset = 0;

    if( (iConf == NULL) ||
        (inputFile == NULL) ||
        (outputFile == NULL))
    {
        /* XXX */
        return 1;
    }
    
    /* open source file */
    if( (iConf->inputfd = open(inputFile,O_RDONLY)) <0 )
    {
	/* XXX */
	perror("open()");
	return 1;
    }
    
    /* get stats */
    if( fstat(iConf->inputfd,&iConf->inputStat) <0)
    {
	/* XXX */
	perror("fstat()");
	return 1;
    }
    
    if( stat(outputFile,&iConf->outputStat) < 0)
    {
	if(errno != ENOENT)
	{
	    perror("stat()");
	    return 1;
	}
    }
    else
    {
	printf("ERROR: [%s()]: File [%s] exist, will not overwrite \n",
	       __FUNCTION__,
	       outputFile);
	return 1;
    }



    /* create dest file, and check if we can write that mutch */
    if( (iConf->outputfd = open(outputFile,O_RDWR|O_CREAT|O_TRUNC,S_IRUSR|S_IRUSR)) <0)
    {
	/* XXX */
	perror("open()");
	return 1;
    }

    /* test avail size */
    if(iConf->write_buffer_length > iConf->inputStat.st_size)
    {
	write_offset = iConf->inputStat.st_size;
    }
    else
    {
	write_offset = iConf->write_buffer_length;
    }
    
    while(current_offset < iConf->inputStat.st_size)
    {
	if( (current_offset + write_offset) > iConf->inputStat.st_size)
	{
	    write_offset = iConf->inputStat.st_size - current_offset;
	}
	
	current_offset += write_offset;
	
	if( write(iConf->outputfd,iConf->write_buffer,write_offset) < 0)
	{
	    /* XXX */
	    printf("ERROR: [%s()]: Not enough space to write zero'ed destination file \n",__FUNCTION__);
	    perror("write()");
	    return 1;
	}
    }

    /* Lets step back for processing */
    
    if( lseek(iConf->outputfd,0,SEEK_SET) < 0)
    {
	perror("lseek()");
	return 1;
    }
    
    if( lseek(iConf->inputfd,0,SEEK_SET) < 0)
    {
	perror("lseek()");
	return 1;
    }
    
    return 0;
}

u_int32_t ProcessUnified2File(u2AnonConfig *iConf,char *inputFile,char *outputFile)
{
    
    if( (iConf == NULL) ||
	(inputFile == NULL) ||
	(outputFile == NULL))
    {
        /* XXX */ 
	return 1;
    }
    
    /* allocate the write buffer if not existant */
    if( iConf->write_buffer == NULL)
    {
	if(iConf->write_buffer_length == 0)
	{
	    iConf->write_buffer_length = WRITE_BUFFER_DEFAULT_LENGTH;
	}
	
	if( (iConf->write_buffer = (char *)calloc(1,iConf->write_buffer_length)) == NULL)
	{
	    /* XXX */
	    return 1;
	}

	memset(iConf->write_buffer,'\0',iConf->write_buffer_length);

    }
    else
    {
	memset(iConf->write_buffer,'\0',iConf->write_buffer_length);
    }
    
    if(strncmp(inputFile,outputFile,PATH_MAX) == 0)
    {
	/* XXX */
	printf("ERROR: [%s()], Source file [%s] and Destination file [%s] are the same file, unable to process. \n",
	       __FUNCTION__,
	       inputFile,
	       outputFile);
	return 1;
    }
    
    
    if( (u2WriteTest(iConf,inputFile,outputFile)))
    {
	/* XXX */
	return 1;
    }
    
    /* process records */
    if( u2ProcessLoop(iConf))
    {
	/* XXX */
	printf("ERROR: [%s()], Error Processing a unified2 Record, bailing \n",
	       __FUNCTION__);
	return 1;
    }
    
    
    return 0;
}


u_int32_t fileOperation(u2AnonConfig *iConf)
{
    char *outputFile = NULL;
    char *inputFile = NULL;
    char *basenameRef = NULL; /* Pointer in basenameHolder buffer */

    char basenameHolder[PATH_MAX] = {0}; /* Used to get filename to create an output file name if only an output dir is created */

    if(iConf == NULL)
    {
	/* XXX */
	goto f_err;
    }
    
    if( (outputFile=(char *)calloc(1,(PATH_MAX))) == NULL)
    {
	goto f_err;
    }
    
    if( (inputFile=(char *)calloc(1,(PATH_MAX))) == NULL)
    {
	goto f_err;
    }
        
    if(iConf->batchProcess)
    {
	/* Read dir */
        /* get file */
	/* while(Read)
	   {	
	   memset(inputFile,'\0',(PATH_MAX));
	   memset(outputFile,'\0',(PATH_MAX));
	   memset(basenameHolder,'\0',(PATH_MAX));
	   if( (ProcessUnified2File(input,output,flag)) == NULL)
	   {
	   return 1;
	   }
	   
	   }
	*/
    }
    else
    {
	if(iConf->inputFile != NULL)
	{
	    memcpy(basenameHolder,iConf->inputFile,strlen(iConf->inputFile));
	    basenameRef = basename(basenameHolder);
	}
	else
	{
	    goto f_err;
	}
	
	if(iConf->outputFile)
	{
	    strncpy(outputFile,iConf->outputFile,PATH_MAX);
	}
	else if( (iConf->outputFile == NULL) && 
		 (iConf->outputDirectory != NULL))
	{
	    snprintf(outputFile,PATH_MAX,"%s%s",
		     iConf->outputDirectory,
		     basenameRef);		
	}
	else
	{
	    /* XXX */
	    return 1;
	}
	
	
	memcpy(inputFile,iConf->inputFile,strlen(iConf->inputFile)+1);
	
	if( (ProcessUnified2File(iConf,inputFile,outputFile)))
	{
	    /* XXX */
	  return 1;
	}
    }
    
    
    if(outputFile != NULL)
    {
        free(outputFile);
	outputFile = NULL;
    }
    
    if(inputFile != NULL)
    {
        free(inputFile);
	inputFile= NULL;
    }
    
    return 0;

 f_err:

     if(outputFile != NULL)
     {
	 free(outputFile);
	 outputFile = NULL;
     }

     if(inputFile != NULL)
     {
	 free(inputFile);
	 inputFile= NULL;
     }
     
    return 1;
}

/* For dynamic packet decoding .. */
void DecoderSet(packetDecodeInstrumentation *iPdi)
{
    if(iPdi == NULL)
    {
	/* XXX */
	return;
    }
    
    memset(iPdi,'\0',(sizeof(packetDecodeInstrumentation)*DLT_MAX));    
    

    iPdi[DLT_EN10MB].decodePtr = DecodeEthPkt;

    iPdi[DLT_IPV4].decodePtr = DecodeEthPkt;
    iPdi[DLT_RAW].decodePtr = DecodeEthPkt;

    iPdi[DLT_IPV6].decodePtr = DecodeRawPkt6; 

    iPdi[DLT_NULL].decodePtr = DecodeNullPkt;
    iPdi[DLT_LOOP].decodePtr = DecodeNullPkt;

    iPdi[DLT_IEEE802_11].decodePtr = DecodeIEEE80211Pkt;

    iPdi[DLT_ENC].decodePtr = DecodeEncPkt;

    iPdi[13].decodePtr = DecodeTRPkt;
    iPdi[DLT_IEEE802].decodePtr = DecodeTRPkt;

    iPdi[DLT_FDDI].decodePtr = DecodeFDDIPkt;
    
    iPdi[DLT_CHDLC].decodePtr = DecodeChdlcPkt;
     
    iPdi[DLT_SLIP].decodePtr = DecodeSlipPkt;

    iPdi[DLT_PPP_SERIAL].decodePtr =  DecodePppSerialPkt;

    iPdi[DLT_LINUX_SLL].decodePtr = DecodeLinuxSLLPkt;

    iPdi[DLT_PFLOG].decodePtr = DecodePflog;

    iPdi[DLT_PPP].decodePtr = DecodePppPkt;

#ifdef DLT_I4L_IP
    iPdi[DLT_I4L_IP].decodePtr = DecodeEthPkt;
#endif /* DLT_I4L_IP */

#ifdef DLT_I4L_CISCOHDLC
    iPdi[DLT_I4L_CISCOHDLC].decodePtr = DecodeI4LCiscoIPPkt;
#endif /* DLT_I4L_CISCOHDLC */

#ifdef DLT_I4L_RAWIP
    iPdi[DLT_I4L_RAWIP].decodePtr =  DecodeI4LRawIPPkt;
#endif /* DLT_I4L_RAWIP */

#ifdef DLT_OLDPFLOG
    iPdi[DLT_OLDPFLOG].decodePtr = DecodeOldPflog;
#endif /* DLT_OLDPFLOG */

    return;
}


/*
 *
 *
 *
 */
int main(int argc, char **argv)
{
    /* Mainly only for safety */
    setupSignal();
    
    /* Initialize decoder's */
    DecoderSet(dInstr);
    
    banner(argc,argv);
    
    if( (u2AnonContext = parseCommandLine(argc,argv)) == NULL)
    {
	/* XXX */
	CleanExit(1);
    }
    
    if(u2AnonContext->verbose_flag)
    {
	printContext(u2AnonContext);
    }

    if( fileOperation(u2AnonContext))
    {
	/* XXX */
	CleanExit(1);
    }
    
    
    CleanExit(0); 
    /* Exit here but remove the compile warn ...*/
    return 0;
}
