/*************************************************************************
    > File Name: mysql-session.cxx
    > Author: jige003
 ************************************************************************/

#include "mysql_session.h"
#include "mysql_parser.h"
#include "mysql_api.h"
#include "util.h"

session_map_t session_map;

Tunnel::Tunnel( struct ip* piphdr, struct tcphdr* ptcphdr, const uint8_t* pkt_data, unsigned int data_len ) :
    data_len( data_len )
{
    char    s_ip[20] = { 0 }, d_ip[20] = { 0 };
    int dport = 0, sport = 0;
    strcpy( s_ip, inet_ntoa( piphdr->ip_src ) );
    strcpy( d_ip, inet_ntoa( piphdr->ip_dst ) );
    sport   = ntohs( ptcphdr->source );
    dport   = ntohs( ptcphdr->dest );
    char buf[1024] = { 0 };
    memset( buf, 0, sizeof(buf) );
    sprintf( buf, "%s:%d-%s:%d", s_ip, sport, d_ip, dport );
    this->rkey   = std::string( buf );
    if ( sport < dport )
    {
        sprintf( buf, "%s:%d-%s:%d", d_ip, dport, s_ip, sport );
    }

    this->dport = dport;
    this->key   = std::string( buf );

    this->ptcphdr = (struct tcphdr*) malloc( sizeof(struct tcphdr) );
    memset( this->ptcphdr, 0, sizeof(struct tcphdr) );
    memcpy( (void*) this->ptcphdr, (void*) ptcphdr, sizeof(struct tcphdr) );

    this->piphdr = (struct ip*) malloc( sizeof(struct ip) );
    memset( this->piphdr, 0, sizeof(struct ip) );
    memcpy( (void*) this->piphdr, (void*) piphdr, sizeof(struct ip) );
    if ( data_len == 0 )
    {
        this->pkt_data = nullptr;
    }
    else
    {
        this->pkt_data = (const uint8_t*) malloc( sizeof(uint8_t) * data_len );
        memset( (uint8_t*) this->pkt_data, 0, sizeof(uint8_t) * data_len );
        memcpy( (void*) this->pkt_data, (void*) pkt_data, data_len );
    }
    this->is_mysql = is_mysql_handle( pkt_data, data_len );
    this->direct = REQ_TYPE;
}

Tunnel::~Tunnel()
{
    XFREE( this->ptcphdr );
    if ( !this->piphdr )
    {
        free( (void*) this->piphdr );
    }

    if ( !this->pkt_data )
    {
        free( (void*) this->pkt_data );
    }
}


inline bool Tunnel::operator ==( const Tunnel & tunnel ) const
{
    if ( this->rkey.compare( tunnel.rkey ) == 0 )
    {
        return (true);
    }

    return (false);
}

std::ostream & operator<<( std::ostream & out, Tunnel & t )
{
    out << t.to_string();
    return (out);
}

bool is_establish_success( vec_tunnel_t & vec )
{
    if ( vec[0].ptcphdr->syn &&
            !vec[0].ptcphdr->ack &&
            vec[1].ptcphdr->syn &&
            vec[1].ptcphdr->ack &&
            !vec[2].ptcphdr->syn &&
            vec[2].ptcphdr->ack
       )
    {
        return (true);
    }
    return (false);
}

bool is_quit_success( vec_tunnel_t & vec )
{
    auto size = vec.size();

    if (
        vec[size - 1].ptcphdr->ack  &&
        vec[size - 2].ptcphdr->ack &&
        vec[size - 2].ptcphdr->fin  &&
        vec[size - 3].ptcphdr->ack &&
        vec[size - 3].ptcphdr->fin
    )
    {
        return (true);
    }
    return (false);
}

void Session::mysql_handshake_handle( Tunnel & t )
{
    if ( !t.is_mysql )
        return;

    if ( t.direct == RESP_TYPE)
    {
        char *buf = NULL;
        buf = mysql_greet_parser( t.pkt_data, t.data_len );
        if (buf)
        {
            this->output = " [ greet handshake ] " + std::string(buf);
        }
    }
    else
    {
        mysql_login_t* login = NULL;
        if ( ( login = mysql_login_parser( t.pkt_data, t.data_len ) ))
        {
            this->state = SESSION_QUERY;
            this->login = login;
            this->db = std::string((const char*)login->schema);
            this->user = std::string((const char*)login->username);
            char str[BUFLEN] =  {0};
            char* password_hex = ts_bin2hex( login->password, sizeof(login->password) );
            sprintf(str, "user: %s  password: %s dbname: %s client_auth_plugin: %s",
                    login->username,
                    password_hex,
                    login->schema,
                    login->client_auth_plugin
                   );
            this->output = " [ login handshake ] " + std::string(str);
        }
    }
}

void Session::mysql_query_handle( Tunnel & t )
{
    if ( !t.is_mysql )
        return;

    if ( t.direct == REQ_TYPE )
    {
        int r = 0;
        char *str = NULL;
        str = mysql_query_req_parser( t.pkt_data, t.data_len, &r);
        if (!str ) return;
        if (r == 1)
        {
            this->state = SESSION_PRE_STMT_RESP;
            this->output = " [ stmt query ] ";
        }
        else
        {
            this->output = " [ normal query ] ";
        }

        this->output += std::string(str);
        XFREE(str);
    }
}


void Session::mysql_pre_stmt_resp( Tunnel & t )
{
    if ( t.direct == RESP_TYPE )
    {
        mysql_stmt_prepare_resp_header_t* mysql_stmt_prepare_resp_header = nullptr;
        mysql_stmt_prepare_resp_header =  mysql_pre_stmt_resp_parser( t.pkt_data, t.data_len );
        if (mysql_stmt_prepare_resp_header)
        {

            dbg( "mysql_pre_stmt_resp_parser ok!" );
            this->state = SESSION_PRE_EXE;
            this->mysql_stmt_prepare_resp_header = mysql_stmt_prepare_resp_header;
        }
    }
}


void Session::mysql_pre_exe_handle( Tunnel & t )
{
    if ( !t.is_mysql )
        return;

    if ( t.direct == REQ_TYPE )
    {
        char *p = NULL;
        if ( ( p =  mysql_pre_exe_parser( t.pkt_data, t.data_len, this->mysql_stmt_prepare_resp_header )  ))
        {
            this->output = " [ stmt exe params ] " + std::string(p);
            XFREE(p);
        }
    }
}


Session::Session( std::string key, Tunnel & t ) : key( key )
{
    this->tunnel_handle( t );
}


void Session::tunnel_handle( Tunnel & t )
{
    this->rkey = t.rkey;
    auto vec_size = this->tvec.size();
    if (vec_size == 0 &&
            t.ptcphdr->syn &&
            !t.ptcphdr->ack
       )
    {
        t.direct = REQ_TYPE;
    }
    else
    {

        if ( t == this->tvec[0])
        {
            t.direct = REQ_TYPE;
        }
        else
        {
            t.direct = RESP_TYPE;

        }
    }
    this->tvec.push_back( t );

    vec_size = this->tvec.size();



    if ( vec_size < 3 )
    {
        this->state = SESSION_ESTABLISH;
    }
    else if ( vec_size == 3 && is_establish_success( this->tvec ) )
    {
        this->state = SESSION_LOFIN;
    }
    else if ( vec_size > 6 && is_quit_success( this->tvec ) )
    {
        this->state = SESSION_QUIT;
    }
}

void Session::mysql_output()
{

    if (this->output.empty()) return;

    std::stringstream buf;
    buf << std::string(now())
        << " "
        << this->rkey;

    if (!this->db.empty() )
    {
        buf << " db: " << this->db
            << " user: " << this->user;
    }
    buf << this->output;
    std::cout << buf.str() << std::endl;
    this->output.clear();
}

void mysql_session_handle( struct ip* piphdr, struct tcphdr* ptcphdr, const uint8_t* pkt_data, unsigned int data_len)
{
    Tunnel t( piphdr, ptcphdr, pkt_data, data_len );
    session_map_iter_t  it = session_map.find( t.key );
    Session         *ss;
    if ( it == session_map.end() )
    {
        Session ses( t.key );
        session_map.insert( { t.key, ses } );
    }

    it  = session_map.find( t.key );
    ss  = &it->second;
    ss->tunnel_handle( t );

    dbg("[ session ] %s\n", ss->to_string().c_str() );
    dbg("[ tunnel ] %s\n\n\n", t.to_string().c_str());

    switch ( ss->state )
    {
    case SESSION_ESTABLISH:
    case SESSION_LOFIN:
        ss->mysql_handshake_handle( t );
        break;
    case SESSION_QUERY:
        ss->mysql_query_handle( t );
        break;
    case SESSION_PRE_STMT_RESP:
        ss->mysql_pre_stmt_resp( t );
        break;
    case SESSION_PRE_EXE:
        ss->mysql_pre_exe_handle( t );
        break;
    case SESSION_QUIT:
        dbg( "session quit! session_map delete key:%s\n", ss->key.c_str() );
        session_map.erase( ss->key );
        ss = NULL;
        break;
    default:
        dbg( "error session occur\n" );
        break;
    }
    if (!ss) return;

    ss->mysql_output();
}
