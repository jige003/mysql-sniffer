/*************************************************************************
    > File Name: util.h
    > Author: jige003
 ************************************************************************/

#ifndef _UTIL_H
#define _UTIL_H
#include <stdint.h>
#include <stddef.h>

#include "macro.h"

__BEGIN_DECLS

char* now();

void hex_debug(const uint32_t *data, size_t len);

int string2int(char *str);

bool isstr(char *str, int len);

char* ts_bin2hex( const unsigned char *old, const size_t oldlen );

void debug_hex_data( const uint8_t* pkt_data, uint32_t data_len );

__END_DECLS

#endif
