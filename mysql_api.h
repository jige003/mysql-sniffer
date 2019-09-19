/*************************************************************************
    > File Name: mysql_api.h
    > Author: jige003
 ************************************************************************/

#ifndef _MYSQL_API_H
#define _MYSQL_API_H
#include "macro.h"
#include "sniffer.h"

__BEGIN_DECLS

void mysql_session_handle( struct ip* piphdr, struct tcphdr* ptcphdr, const uint8_t* pkt_data, unsigned int data_len);

__END_DECLS


#endif
