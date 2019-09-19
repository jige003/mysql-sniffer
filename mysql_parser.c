/*************************************************************************
    > File Name: mysql-parser.c
    > Author: jige003
 ************************************************************************/

#include<stdio.h>
#include <stdint.h>

#include "macro.h"
#include "mysql_parser.h"
#include "sniffer.h"
#include "util.h"

uint8_t* get_str( const uint8_t** p, uint32_t *data_len )
{
    uint8_t* buffer = (uint8_t*) malloc( 1024 * sizeof(uint8_t) );
    memset( buffer, 0, 1024 * sizeof(uint8_t) );
    uint8_t* buf = buffer;
    while ( **p && (*data_len) > 0 )
    {
        *(buf++) = *( (*p)++);
        (*data_len)--;
    }
    ;
    (*p)++;
    *buf = '\0';
    return (buffer);
}

void mysql_greet_free( mysql_greet_t* greet )
{
    XFREE( greet->version );
    XFREE( greet->salt );
    XFREE( greet->salt1 );
    XFREE( greet->auth_plugin );
}

bool is_mysql_handle( const uint8_t* pkt_data, uint32_t data_len )
{
    if ( data_len < MYSQL_HEADER_LEN )
        return (false);

    mysql_header_t *mysql_header = (mysql_header_t *) pkt_data;
    if ( mysql_header->len != (data_len - MYSQL_HEADER_LEN) )
        return (false);

    return (true);
}

char* mysql_greet_parser( const uint8_t* pkt_data, uint32_t data_len )
{
    if ( data_len < (sizeof(mysql_greet_t) / 8 + MYSQL_HEADER_LEN) )
        return (NULL);

    static char buf[BUFLEN];
    mysql_greet_t* greet = (mysql_greet_t*) malloc( sizeof(mysql_greet_t) );
    memset( greet, 0, sizeof(mysql_greet_t) );

    const uint8_t* p = pkt_data + MYSQL_HEADER_LEN;
    memcpy_int_x( greet->protocal, p, 1, data_len );
    memcpy_str_x( greet->version, p, data_len );
    memcpy_int_x( greet->thread_id, p, 4, data_len );
    memcpy_str_x( greet->salt, p, data_len );
    memcpy_int_x( greet->capabilities, p, 2, data_len );
    memcpy_int_x( greet->language, p, 1, data_len );
    memcpy_int_x( greet->status, p, 2, data_len );
    memcpy_int_x( greet->ext_capabilities, p, 2, data_len );
    memcpy_int_x( greet->auth_plugin_len, p, 1, data_len );
    memcpy_int_x( greet->unused1, p, 8, data_len );
    memcpy_int_x( greet->unused2, p, 2, data_len );
    memcpy_str_x( greet->salt1, p, data_len );
    memcpy_str_x( greet->auth_plugin, p, data_len );

    dbg( "\tprotocal:%d \n\tversion:%s \n\tthread_id:%d \n\tsalt:%s \n\tsalt1:%s \n\tauth_plugin:%s\n",
         greet->protocal,
         greet->version,
         greet->thread_id,
         greet->salt,
         greet->salt1,
         greet->auth_plugin
       );
    sprintf(buf, "protocal: %d  version: %s auth_plugin: %s ",
            greet->protocal,
            greet->version,
            greet->auth_plugin
           );
    mysql_greet_free( greet );
    return buf;
}

void mysql_login_t_free(mysql_login_t* loginp)
{
    if (loginp)
    {

        XFREE(loginp->username);
        XFREE(loginp->schema);
        XFREE(loginp->client_auth_plugin);
    }
    XFREE(loginp);
}

mysql_login_t* mysql_login_parser( const uint8_t* pkt_data, uint32_t data_len )
{
    if ( data_len < (sizeof(mysql_login_t) / 8 + MYSQL_HEADER_LEN) )
        return (NULL);
    mysql_login_t* login = (mysql_login_t*) malloc( sizeof(mysql_login_t) );
    memset( login, 0, sizeof(mysql_login_t) );

    const uint8_t* p = pkt_data + MYSQL_HEADER_LEN;
    memcpy_int_x( login->client_capabilities, p, 2, data_len );
    memcpy_int_x( login->ext_client_capabilities, p, 2, data_len );
    memcpy_int_x( login->max_packet, p, 4, data_len );
    memcpy_int_x( login->charset, p, 1, data_len );
    memcpy_int_x( login->unused, p, 23, data_len );
    memcpy_str_x( login->username, p, data_len );
    p++;
    data_len--;
    memcpy_int_x( login->password, p, 20, data_len );
    memcpy_str_x( login->schema, p, data_len );
    memcpy_str_x( login->client_auth_plugin, p, data_len );

    char* password_hex = ts_bin2hex( login->password, sizeof(login->password) );
    dbg( "\tuser:%s \n\tpassword:%s \n\tdbname:%s \n\tclient_auth_plugin:%s\n",
         login->username,
         password_hex,
         login->schema,
         login->client_auth_plugin
       );
    XFREE( password_hex );
    return login;
}

void mysql_query_t_free( mysql_query_t* mysql_query )
{
    XFREE( mysql_query->cmd );
}

/*
 * 0 normal query
 * 1 stmt prepae
 * -1 error
 */

char* mysql_query_req_parser( const uint8_t* pkt_data, uint32_t data_len, int *r )
{
    if ( data_len < (MYSQL_HEADER_LEN + sizeof(mysql_query_t) / 8) )
        return (NULL);

    mysql_query_t* mysql_query = (mysql_query_t*) malloc( sizeof(mysql_query_t) );
    memset( mysql_query, 0, sizeof(mysql_query_t) );
    int x = 1;
    *r = 0;

    const uint8_t* p = pkt_data + MYSQL_HEADER_LEN;
    data_len -= MYSQL_HEADER_LEN;
    memcpy_int_x( mysql_query->cmd_type, p, 1, data_len );
    switch ( mysql_query->cmd_type )
    {
#define REQ_TYPE_HADNLE( type ) \
case type: \
    x = 0; \
    break;
        REQ_TYPE_HADNLE( COM_STATISTICS )
        REQ_TYPE_HADNLE( COM_QUIT )
        REQ_TYPE_HADNLE( COM_INIT_DB )
        REQ_TYPE_HADNLE( COM_QUERY )
        REQ_TYPE_HADNLE( COM_FIELD_LIST )
        REQ_TYPE_HADNLE( COM_CREATE_DB )
        REQ_TYPE_HADNLE( COM_DROP_DB )
        REQ_TYPE_HADNLE( COM_REFRESH )
        REQ_TYPE_HADNLE( COM_PROCESS_INFO )
        REQ_TYPE_HADNLE( COM_PROCESS_KILL )
        REQ_TYPE_HADNLE( COM_DEBUG )
    case COM_STMT_PREPARE:
        /*s->state    = SESSION_PRE_STMT_RESP;*/
        *r = 1;
        x       = 0;
        break;
        REQ_TYPE_HADNLE( COM_STMT_EXECUTE )
        REQ_TYPE_HADNLE( COM_STMT_SEND_LONG_DATA )
        REQ_TYPE_HADNLE( COM_STMT_CLOSE )
        REQ_TYPE_HADNLE( COM_STMT_RESET )
        REQ_TYPE_HADNLE( COM_SET_OPTION )
        REQ_TYPE_HADNLE( COM_STMT_FETCH )
    default:
        dbg( "unknown type: %d\n", mysql_query->cmd_type );
        break;
    }
    if ( x || !*p )
        return (NULL);

    memcpy_str_x( mysql_query->cmd, p, data_len );


    dbg( "\tmysql cmd_type:%d \n\tmysql cmd:%s\n ",
         mysql_query->cmd_type,
         mysql_query->cmd
       );
    char *str = (char*)calloc(strlen((const char*)mysql_query->cmd), sizeof(char));
    memcpy(str, mysql_query->cmd, strlen((const char*)mysql_query->cmd));
    mysql_query_t_free( mysql_query );
    return str;
}

mysql_stmt_prepare_resp_header_t* mysql_pre_stmt_resp_parser( const uint8_t* pkt_data, uint32_t data_len )
{
    if ( data_len < (sizeof(mysql_stmt_prepare_resp_header_t) / 8 + MYSQL_HEADER_LEN) )
        return (NULL);
    const uint8_t* p = pkt_data + MYSQL_HEADER_LEN;
    data_len -= MYSQL_HEADER_LEN;
    /*debug_hex_data(p, data_len); */

    mysql_stmt_prepare_resp_header_t* mysql_stmt_prepare_resp_header = (mysql_stmt_prepare_resp_header_t*) malloc( sizeof(mysql_stmt_prepare_resp_header_t) );
    memset( mysql_stmt_prepare_resp_header, 0, sizeof(mysql_stmt_prepare_resp_header_t) );

    memcpy_int_x( mysql_stmt_prepare_resp_header->status, p, 1, data_len );
    memcpy_int_x( mysql_stmt_prepare_resp_header->statement_id, p, 4, data_len );
    memcpy_int_x( mysql_stmt_prepare_resp_header->num_cols, p, 2, data_len );
    memcpy_int_x( mysql_stmt_prepare_resp_header->num_params, p, 2, data_len );
    dbg( "\tstatement_id:%d \n\tnum_cols:%d \n\tnum_params:%d \n",
         mysql_stmt_prepare_resp_header->statement_id,
         mysql_stmt_prepare_resp_header->num_cols,
         mysql_stmt_prepare_resp_header->num_params
       );
    /*s->mysql_stmt_prepare_resp_header   = mysql_stmt_prepare_resp_header;*/
    /*s->state                = SESSION_PRE_EXE;*/
    /*XFREE(mysql_stmt_prepare_resp_header); */
    return mysql_stmt_prepare_resp_header;
}


char* mysql_stmt_param_parser( const uint8_t* pkt_data, uint32_t data_len, mysql_stmt_prepare_resp_header_t* mysql_stmt_prepare_resp_header )
{
    const uint8_t   *p      = pkt_data;
    uint32_t    num_params  = 0,
                params_len  = 0,
                i       = 0,
                s_len       = 0;
    uint8_t     tinyint     = 0;
    uint16_t    smallint    = 0;
    uint32_t    normalint   = 0;
    uint64_t    bigint      = 0;
    float       fint        = 0;
    double      dint        = 0;

    if ( !mysql_stmt_prepare_resp_header )
    {
        dbg( "mysql_stmt_prepare_resp_header exception\n" );
        return (NULL);
    }
    num_params = mysql_stmt_prepare_resp_header->num_params;
    dbg( "stmt num_params:%d\n", num_params );
    params_len = num_params * 2;
    mysql_stmt_param_t param_arr[num_params];
    memset( &param_arr, 0, sizeof(param_arr) );

    char buf[num_params][COLUMN_COMMENT_MAXLEN];
    memset(buf, 0, sizeof(buf));

    for ( i = 0; i < num_params; i++ )
    {
        memcpy( (void*) &param_arr[i].buffer_type, (void*) (p + i * 2), 1 );
    }

    p += params_len;

    for ( i = 0; i < num_params; i++ )
    {
        switch ( param_arr[i].buffer_type )
        {
            STMT_BUFFER_STR_PARSER( MYSQL_TYPE_STRING, param_arr[i].buffer, buf[i], p, s_len, data_len );
            STMT_BUFFER_STR_PARSER( MYSQL_TYPE_VAR_STRING, param_arr[i].buffer, buf[i], p, s_len, data_len );
            STMT_BUFFER_STR_PARSER( MYSQL_TYPE_NEWDECIMAL, param_arr[i].buffer, buf[i], p, s_len, data_len );
            STMT_BUFFER_INTX_PARSER( MYSQL_TYPE_TINY, param_arr[i].buffer, buf[i], p, tinyint, 1, data_len, "%d" );

            STMT_BUFFER_INTX_PARSER( MYSQL_TYPE_SHORT, param_arr[i].buffer, buf[i], p, smallint, 2, data_len, "%d" );
            STMT_BUFFER_INTX_PARSER( MYSQL_TYPE_LONG, param_arr[i].buffer, buf[i], p, normalint, 4, data_len, "%d" );
            STMT_BUFFER_INTX_PARSER( MYSQL_TYPE_INT24, param_arr[i].buffer, buf[i], p, normalint, 4, data_len, "%d" );
            STMT_BUFFER_INTX_PARSER( MYSQL_TYPE_FLOAT, param_arr[i].buffer, buf[i], p, fint, 4, data_len, "%f" );
            STMT_BUFFER_INTX_PARSER( MYSQL_TYPE_DOUBLE, param_arr[i].buffer, buf[i], p, dint, 8, data_len, "%f" );
            STMT_BUFFER_INTX_PARSER( MYSQL_TYPE_LONGLONG, param_arr[i].buffer, buf[i], p, bigint, 8, data_len, "%ld" );
        default:
            dbg( "enum_field_types no parser: %d\n", param_arr[i].buffer_type );
            break;
        }
    }
    int r = 0;
    for ( i = 0; i < num_params; i++ )
    {
        dbg( "\tnum_params:%d \n\t buffer_type:%d buffer:%s\n",
             i,
             param_arr[i].buffer_type,
             (char*) param_arr[i].buffer
           );
        r += strlen( (char*) param_arr[i].buffer);
    }

    r += BUFLEN;

    char *str = (char*)calloc(r, sizeof(char));
    char tmp[BUFLEN] = {0};
    sprintf(tmp, "num_params: %d", num_params);
    strncat(str, tmp, strlen(tmp));
    *(str + strlen(tmp) ) = ' ';

    for ( i = 0; i < num_params; i++ )
    {
        sprintf(tmp, "params<%d>: %s", i,  (char*) param_arr[i].buffer);
        strncat(str, tmp, strlen(tmp));
        *(str + strlen(str) ) = ' ';
    }
    *(str + strlen(str) ) = '\0';

    return (str);
}


char* mysql_pre_exe_parser( const uint8_t* pkt_data, uint32_t data_len, mysql_stmt_prepare_resp_header_t* mysql_stmt_prepare_resp_header)
{
    if ( data_len < (sizeof(mysql_stmt_exe_header_t) / 8 + MYSQL_HEADER_LEN) )
        return (NULL);
    const uint8_t* p = pkt_data + MYSQL_HEADER_LEN;
    data_len -= MYSQL_HEADER_LEN;

    mysql_stmt_exe_header_t* mysql_stmt_exe_header = (mysql_stmt_exe_header_t*) malloc( sizeof(mysql_stmt_exe_header_t) );
    memset( mysql_stmt_exe_header, 0, sizeof(mysql_stmt_exe_header_t) );

    memcpy_int_x( mysql_stmt_exe_header->cmd_type, p, 1, data_len );

    if ( mysql_stmt_exe_header->cmd_type != COM_STMT_EXECUTE )
        goto err;

    memcpy_int_x( mysql_stmt_exe_header->statement_id, p, 4, data_len );
    memcpy_int_x( mysql_stmt_exe_header->flag, p, 1, data_len );
    memcpy_int_x( mysql_stmt_exe_header->iterations, p, 4, data_len );
    memcpy_int_x( mysql_stmt_exe_header->unused, p, 1, data_len );
    memcpy_int_x( mysql_stmt_exe_header->bound, p, 1, data_len );

    dbg( "\tcmd_type:%d \n\tstatement_id:%d \n\tbound:%d \n\t   \n",
         mysql_stmt_exe_header->cmd_type,
         mysql_stmt_exe_header->statement_id,
         mysql_stmt_exe_header->bound
       );
    if ( !mysql_stmt_exe_header->bound )
    {
        goto err;
    }

    return mysql_stmt_param_parser( p, data_len, mysql_stmt_prepare_resp_header);

err:
    XFREE( mysql_stmt_exe_header );
    return (NULL);
}
