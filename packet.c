/*************************************************************************
    > File Name: packet.c
    > Author: jige003
 ************************************************************************/

#include "sniffer.h"
#include "macro.h"
#include "mysql_api.h"

void tuple4_p(tuple4* tp)
{
    (void)tp;
    char sip[20] = {0}, dip[20] = {0};

    strcpy(sip, int_ntoa(tp->sip));
    strcpy(dip, int_ntoa(tp->dip));
    dbg("%s:%d-%s:%d\n", sip, tp->sport, dip, tp->dport);
}

void process_tcp_packet(const uint8_t* packet, uint32_t len, uint32_t offset)
{
    (void)len;
    struct ip       * piphdr = NULL;
    uint32_t data_len = 0;

    piphdr      = (struct ip*) (packet + offset);
    offset += IP_HL( piphdr );

    data_len    = ntohs( piphdr->ip_len ) - IP_HL( piphdr );

    struct tcphdr       * ptcphdr;
    ptcphdr     = (struct tcphdr*) (packet + offset);
    offset += TCP_OFF( ptcphdr );
    data_len    = data_len - TCP_OFF( ptcphdr );

    /* tuple4 addr;*/
    /*addr.sip = piphdr->ip_src.s_addr;*/
    /*addr.dip = piphdr->ip_dst.s_addr;*/
    /*addr.sport = ntohs( ptcphdr->source );*/
    /*addr.dport = ntohs( ptcphdr->dest );*/

    /*tuple4_p(&addr);*/

    const uint8_t* p = packet + offset;

    mysql_session_handle(piphdr, ptcphdr, p, data_len);
}
