/*************************************************************************
    > File Name: sniffer.h
    > Author: jige003
 ************************************************************************/

#ifndef _SNIFFER_H
#define _SNIFFER_H
#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>

__BEGIN_DECLS

#define BUFLEN 1024

#define DEFAULT_MYSQL_PORT 3306

#define TRUE "true"

#define SUCCESS 0
#define ERROR 1

#define TCP_OFF( tcp ) (tcp->doff * sizeof(uint32_t) )

#define IP_HL( ip ) ( (4 * ip->ip_hl) )

#define int_ntoa(x) inet_ntoa(*((struct in_addr *)&x))

typedef struct
{
    char    *device;
    char    bufstr[BUFLEN];
    int port;

} option_t;

typedef struct
{
    uint32_t sip, dip;
    uint16_t sport, dport;
} tuple4;

extern bool debug;

void init(void) __attribute__((constructor));

void usage(char* prog_name);

pcap_t* init_pcap_t( char* device, const char* bpfstr );

void sniff_loop( pcap_t* pHandle, pcap_handler func );

void packetHandle( u_char* arg, const struct pcap_pkthdr* header, const u_char* pkt_data );

__END_DECLS

#endif
