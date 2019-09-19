/*************************************************************************
    > File Name: sniffer.c
    > Author: jige003
 ************************************************************************/
#include <stdbool.h>

#include "macro.h"
#include "sniffer.h"
#include "packet.h"

bool debug = false;

void init(void)
{
    char *d = getenv( "jdebug" );
    if ( d != NULL && !strncmp( d, TRUE, strlen(TRUE) ) )
        debug = true;

    dbg( "debug mode\n" );
}


void usage(char* prog_name)
{
    fprintf( stderr, "Copyright by jige003\n\n" );
    fprintf( stderr, "Usage:\n" );
    fprintf( stderr, "\t%s [-h] -i interface -p port\n\n",  prog_name);
}

pcap_t* init_pcap_t( char* device, const char* bpfstr )
{
    char    errBuf[PCAP_ERRBUF_SIZE];
    pcap_t  *pHandle;

    uint32_t        netmask = -1;
    struct bpf_program  bpf;

    if ( !*device && !(device = pcap_lookupdev( errBuf ) ) )
    {
        printf( "pcap_lookupdev(): %s\n", errBuf );
        return (NULL);
    }

    printf( "[*] sniffe on interface: %s\n", device );

    if ( (pHandle = pcap_open_live( device, 65535, 1, 0, errBuf ) ) == NULL )
    {
        printf( "pcap_open_live(): %s\n", errBuf );
        return (NULL);
    }


    if ( pcap_compile( pHandle, &bpf, (char*) bpfstr, 0, netmask ) )
    {
        printf( "pcap_compile(): %s\n", pcap_geterr( pHandle ) );
        return (NULL);
    }

    if ( pcap_setfilter( pHandle, &bpf ) < 0 )
    {
        printf( "pcap_setfilter(): %s\n", pcap_geterr( pHandle ) );
        return (NULL);
    }
    return (pHandle);
}

void sniff_loop( pcap_t* pHandle, pcap_handler func )
{
    int linktype, linkhdrlen = 0;

    if ( (linktype = pcap_datalink( pHandle ) ) < 0 )
    {
        printf( "pcap_datalink(): %s\n", pcap_geterr( pHandle ) );
        return;
    }

    switch ( linktype )
    {
    case DLT_RAW:
        linkhdrlen = 0;
        break;

    case DLT_NULL:
        linkhdrlen = 4;
        break;

    case DLT_EN10MB:
        linkhdrlen = 14;
        break;

    case DLT_LINUX_SLL:
        linkhdrlen = 16;
        break;

    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;

    default:
        printf( "Unsupported datalink (%d)\n", linktype );
        return;
    }

    if ( pcap_loop( pHandle, -1, func, (u_char*) &linkhdrlen ) < 0 )
        printf( "pcap_loop failed: %s\n", pcap_geterr( pHandle ) );
}

void packetHandle( u_char* arg, const struct pcap_pkthdr* header, const u_char* pkt_data )
{
    if ( header->caplen < header->len  || !pkt_data)
        return;

    int         *linkhdrlen = (int*) arg;
    uint32_t offset = 0;

    switch (*linkhdrlen)
    {
    case DLT_EN10MB:
        if (header->len < 14) return ;

        if (pkt_data[12] == 8 && pkt_data[13] == 0)
        {
            /* Regular ethernet */
            *linkhdrlen = 14;
        }
        else if (pkt_data[12] == 0x81 && pkt_data[13] == 0)
        {
            /* Skip 802.1Q VLAN and priority information */
            *linkhdrlen = 18;
        }
        else
        {
            /* non-ip frame */
            return;

        }
        break;
    default:
        break;
    }

    if ((int)header->caplen < *linkhdrlen) return;

    offset += *linkhdrlen;

    struct ip       * piphdr = NULL;

    piphdr      = (struct ip*) (pkt_data + offset);

    switch ( piphdr->ip_p )
    {
    case IPPROTO_TCP:
        process_tcp_packet(pkt_data, header->len, offset);
        break;
    default:
        break;
    }
}

int main( int argc, char**argv )
{
    pcap_t* pHandle = NULL;

    int i = 0;

    option_t *option = NULL;
    imalloc(option_t, option)

    char *prog_name = argv[0];
    if ( argc < 2 )
    {
        usage(prog_name);
        return (ERROR);
    }

    while ( (i = getopt( argc, argv, "hi:p:" ) ) != -1 )
    {
        switch ( i )
        {
        case 'h':
            usage(prog_name);
            return (ERROR);
            break;
        case 'i':
            option->device = optarg;
            break;
        case 'p':
            option->port = atoi( optarg );
            break;
        default:
            break;
        }
    }

    if (option->port == 0)
    {
        sprintf( option->bufstr, "port %d", DEFAULT_MYSQL_PORT );
    }
    else
    {
        sprintf( option->bufstr, "port %d", option->port );
    }

    dbg("filter buf:%s\n", option->bufstr);
    if ( (pHandle = init_pcap_t( option->device, option->bufstr ) ) )
    {
        sniff_loop( pHandle, (pcap_handler) packetHandle );
    }

    return (SUCCESS);
}
