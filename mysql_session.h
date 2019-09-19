/*************************************************************************
    > File Name: mysql-session.h
    > Author: jige003
 ************************************************************************/

#ifndef _MYSQL_SESSION_H
#define _MYSQL_SESSION_H
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <ostream>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <sstream>

#include "mysql_parser.h"
#include "macro.h"
#include "sniffer.h"

typedef enum
{
    SESSION_ESTABLISH,
    SESSION_LOFIN,
    SESSION_QUERY,
    SESSION_PRE_STMT,
    SESSION_PRE_STMT_RESP,
    SESSION_PRE_EXE,
    SESSION_PRE_EXE_RESP,
    SESSION_QUIT,
    SESSION_ERROR
} session_state;

typedef enum
{
    REQ_TYPE = 0,
    RESP_TYPE
} conn_direction;


struct Tunnel
{
    std::string key;
    std::string rkey;
    struct ip   * piphdr;
    struct tcphdr   * ptcphdr;
    const uint8_t   * pkt_data;
    unsigned int    data_len;
    conn_direction  direct;
    int     dport;
    bool        is_mysql;

    Tunnel( struct ip* piphdr, struct tcphdr* ptcphdr, const uint8_t* pkt_data, unsigned int data_len );
    ~Tunnel();
    std::string to_string()
    {
        char buf[BUFLEN] = { 0 };
        sprintf( buf, " datalen:%d is_mysql:%d syn:%d ack:%d psh:%d fin:%d dport:%d direct:%d",
                 this->data_len,
                 this->is_mysql,
                 this->ptcphdr->syn,
                 this->ptcphdr->ack,
                 this->ptcphdr->psh,
                 this->ptcphdr->fin,
                 this->dport,
                 this->direct
               );
        std::stringstream out;
        out << "key: "
            << this->key
            << "  rkey: "
            << this->rkey
            << std::string( buf );
        return (out.str() );
    }


    friend std::ostream & operator<<( std::ostream & out, const Tunnel & tunnel );


    inline bool operator ==( const Tunnel & tunnel ) const;
};


typedef std::vector<Tunnel> vec_tunnel_t;

struct Session
{
    std::string key;
    std::string rkey;
    std::string db;
    std::string user;
    std::string output;

    vec_tunnel_t            tvec;
    session_state           state;
    mysql_stmt_prepare_resp_header_t* mysql_stmt_prepare_resp_header;
    mysql_login_t* login;
    Session()
    {
    };
    Session( std::string key, Tunnel & t );
    Session( std::string key ) : key( key )
    {
        this->login = NULL;
        this->mysql_stmt_prepare_resp_header = NULL;
    };
    ~Session()
    {
        std::vector<Tunnel>().swap( this->tvec );
        XFREE( this->mysql_stmt_prepare_resp_header );
        mysql_login_t_free(this->login);
    };
    std::string to_string()
    {
        char buf[BUFLEN] = {0};
        if (this->login)
        {
            if (this->login->username && this->login->schema)
            {
                sprintf(buf, "dbname: %s user: %s",
                        this->login->schema,
                        this->login->username
                       );
            }
        }
        std::stringstream out;
        out << "key: "
            << this->key
            << " rkey: "
            << this->rkey
            << " state: "
            << this->state
            << "  "
            << std::string(buf)
            << "   tvec size:   "
            << this->tvec.size()
            << std::endl;
        for ( auto & x : this->tvec )
        {
            out << "\t\t" << x.to_string() << std::endl;
        }
        return (out.str() );
    }

    void tunnel_handle( Tunnel & t );

    void mysql_handshake_handle( Tunnel & t );

    void mysql_query_handle( Tunnel & t );

    void mysql_pre_stmt_resp( Tunnel & t );

    void mysql_pre_exe_handle( Tunnel & t );

    void mysql_output();
};

typedef std::unordered_map<std::string, Session>    session_map_t;
typedef session_map_t::iterator             session_map_iter_t;

#endif
