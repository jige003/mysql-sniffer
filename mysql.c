#include "mysql.h"

int debug = 0;

void mysql_req_parser(const uint8_t* pkt_data, uint32_t data_len, cb_t cb){
    if (data_len < MYSQL_HEADER_LEN) 
        return;
    mysql_header_t *mysql_header;
    mysql_header = (mysql_header_t *)pkt_data;
    pkt_data += MYSQL_HEADER_LEN;
    dbg("len:%d num: %d \n", mysql_header->len, mysql_header->num);
    
    uint8_t req_type;
    const uint8_t *command;
    int x = 1;
    memcpy(&req_type, pkt_data++, 1);

    switch (req_type) {
#define REQ_TYPE_HADNLE(type) \
case type:\
    x = 0; \
    break; 
        REQ_TYPE_HADNLE(COM_STATISTICS)
        REQ_TYPE_HADNLE(COM_QUIT)
        REQ_TYPE_HADNLE(COM_INIT_DB)
        REQ_TYPE_HADNLE(COM_QUERY)
        REQ_TYPE_HADNLE(COM_FIELD_LIST)
        REQ_TYPE_HADNLE(COM_CREATE_DB)
        REQ_TYPE_HADNLE(COM_DROP_DB)
        REQ_TYPE_HADNLE(COM_REFRESH)
        REQ_TYPE_HADNLE(COM_PROCESS_INFO)
        REQ_TYPE_HADNLE(COM_PROCESS_KILL)
        REQ_TYPE_HADNLE(COM_DEBUG)
        REQ_TYPE_HADNLE(COM_CHANGE_USER)
        REQ_TYPE_HADNLE(COM_STMT_PREPARE)
        REQ_TYPE_HADNLE(COM_STMT_EXECUTE)
        REQ_TYPE_HADNLE(COM_STMT_SEND_LONG_DATA)
        REQ_TYPE_HADNLE(COM_STMT_CLOSE)
        REQ_TYPE_HADNLE(COM_STMT_RESET)
        REQ_TYPE_HADNLE(COM_SET_OPTION)
        REQ_TYPE_HADNLE(COM_STMT_FETCH)
        default:
            dbg("unknown type: %d\n", req_type);   
    }
    if (x || !*pkt_data)
        return ;    

    command = pkt_data;
    dbg("command:%s\n", command);
    if (cb)
        cb("req", (char*)command);
}
