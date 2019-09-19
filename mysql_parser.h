/*************************************************************************
    > File Name: mysql-parser.h
    > Author: jige003
 ************************************************************************/

#ifndef _MYSQL_PARSER_H
#define _MYSQL_PARSER_H
#include <stdint.h>

#include "sniffer.h"

__BEGIN_DECLS

#define HOSTNAME_LENGTH     60
#define COLUMN_COMMENT_MAXLEN       1024

enum enum_server_command
{
    COM_SLEEP, COM_QUIT, COM_INIT_DB, COM_QUERY, COM_FIELD_LIST,
    COM_CREATE_DB, COM_DROP_DB, COM_REFRESH, COM_SHUTDOWN, COM_STATISTICS,
    COM_PROCESS_INFO, COM_CONNECT, COM_PROCESS_KILL, COM_DEBUG, COM_PING,
    COM_TIME, COM_DELAYED_INSERT, COM_CHANGE_USER, COM_BINLOG_DUMP,
    COM_TABLE_DUMP, COM_CONNECT_OUT, COM_REGISTER_SLAVE,
    COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_SEND_LONG_DATA, COM_STMT_CLOSE,
    COM_STMT_RESET, COM_SET_OPTION, COM_STMT_FETCH, COM_DAEMON,
    /* don't forget to update const char *command_name[] in sql_parse.cc */

    /* Must be last */
    COM_END
};

#define packet_error (~(unsigned long) 0)

enum enum_field_types { MYSQL_TYPE_DECIMAL, MYSQL_TYPE_TINY,
                        MYSQL_TYPE_SHORT, MYSQL_TYPE_LONG,
                        MYSQL_TYPE_FLOAT, MYSQL_TYPE_DOUBLE,
                        MYSQL_TYPE_NULL, MYSQL_TYPE_TIMESTAMP,
                        MYSQL_TYPE_LONGLONG, MYSQL_TYPE_INT24,
                        MYSQL_TYPE_DATE, MYSQL_TYPE_TIME,
                        MYSQL_TYPE_DATETIME, MYSQL_TYPE_YEAR,
                        MYSQL_TYPE_NEWDATE, MYSQL_TYPE_VARCHAR,
                        MYSQL_TYPE_BIT,
                        MYSQL_TYPE_NEWDECIMAL   = 246,
                        MYSQL_TYPE_ENUM     = 247,
                        MYSQL_TYPE_SET      = 248,
                        MYSQL_TYPE_TINY_BLOB    = 249,
                        MYSQL_TYPE_MEDIUM_BLOB  = 250,
                        MYSQL_TYPE_LONG_BLOB    = 251,
                        MYSQL_TYPE_BLOB     = 252,
                        MYSQL_TYPE_VAR_STRING   = 253,
                        MYSQL_TYPE_STRING   = 254,
                        MYSQL_TYPE_GEOMETRY = 255
                      };



enum enum_mysql_timestamp_type
{
    MYSQL_TIMESTAMP_NONE        = -2,
    MYSQL_TIMESTAMP_ERROR       = -1,
    MYSQL_TIMESTAMP_DATE        = 0,
    MYSQL_TIMESTAMP_DATETIME    = 1,
    MYSQL_TIMESTAMP_TIME        = 2
};


/*
 * Structure which is used to represent datetime values inside MySQL.
 *
 * We assume that values in this structure are normalized, i.e. year <= 9999,
 * month <= 12, day <= 31, hour <= 23, hour <= 59, hour <= 59. Many functions
 * in server such as my_system_gmt_sec() or make_time() family of functions
 * rely on this (actually now usage of make_*() family relies on a bit weaker
 * restriction). Also functions that produce MYSQL_TIME as result ensure this.
 * There is one exception to this rule though if this structure holds time
 * value (time_type == MYSQL_TIMESTAMP_TIME) days and hour member can hold
 * bigger values.
 */
typedef struct MYSQL_TIME
{
    unsigned int            year, month, day, hour, minute, second;
    unsigned long           second_part; /**< microseconds */
    bool                neg;
    enum enum_mysql_timestamp_type  time_type;
} MYSQL_TIME;


typedef struct
{
    enum enum_field_types   buffer_type;
    void            *buffer;
    uint8_t         buffer_length;
} mysql_stmt_param_t;


typedef struct
{
    uint8_t     status;
    uint32_t    statement_id;
    uint16_t    num_cols;
    uint16_t    num_params;
    uint8_t     reserved_1;
    uint16_t    warning_count;
} mysql_stmt_prepare_resp_header_t;

typedef struct
{
    enum enum_server_command    cmd_type;
    uint32_t            statement_id;
    uint8_t             flag;
    uint32_t            iterations;
    uint8_t             unused;
    uint8_t             bound;
} mysql_stmt_exe_header_t;

typedef struct
{
    uint32_t    len : 24;
    uint8_t     num : 8;
} mysql_header_t;

#define MYSQL_HEADER_LEN 4

/*mysql handshake greet protocal*/
typedef struct
{
    uint8_t     protocal;
    uint8_t     * version;
    uint32_t    thread_id;
    uint8_t     * salt;
    uint16_t    capabilities;
    uint8_t     language;
    uint16_t    status;
    uint16_t    ext_capabilities;
    uint8_t     auth_plugin_len;
    uint64_t    unused1;
    uint16_t    unused2;
    uint8_t     * salt1;
    uint8_t     * auth_plugin;
} mysql_greet_t;

/*mysql handshake login protocal*/
typedef struct
{
    uint16_t    client_capabilities;
    uint16_t    ext_client_capabilities;
    uint32_t    max_packet;
    uint8_t     charset;
    uint8_t     unused[23];
    uint8_t     * username;
    uint8_t     password[20];
    uint8_t     * schema;
    uint8_t     * client_auth_plugin;
} mysql_login_t;

typedef struct
{
    enum enum_server_command    cmd_type;
    uint8_t             * cmd;
} mysql_query_t;

uint8_t* get_str( const uint8_t** p, uint32_t *data_len );

void mysql_greet_free( mysql_greet_t* greet );

bool is_mysql_handle( const uint8_t* pkt_data, uint32_t data_len );

char* mysql_greet_parser( const uint8_t* pkt_data, uint32_t data_len );

mysql_login_t* mysql_login_parser( const uint8_t* pkt_data, uint32_t data_len );

void mysql_login_t_free(mysql_login_t* loginp);

void mysql_query_t_free( mysql_query_t* mysql_query );

char* mysql_query_req_parser( const uint8_t* pkt_data, uint32_t data_len, int *r);

mysql_stmt_prepare_resp_header_t* mysql_pre_stmt_resp_parser( const uint8_t* pkt_data, uint32_t data_len  );

char* mysql_stmt_param_parser( const uint8_t* pkt_data, uint32_t data_len, mysql_stmt_prepare_resp_header_t* mysql_stmt_prepare_resp_header );

char* mysql_pre_exe_parser( const uint8_t* pkt_data, uint32_t data_len, mysql_stmt_prepare_resp_header_t* mysql_stmt_prepare_resp_header);

__END_DECLS

#endif
