/*************************************************************************
    > File Name: util.c
    > Author: jige003
 ************************************************************************/

#include<stdio.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

char* now()
{
    time_t tim;
    struct tm *at;
    static char now[80];
    time(&tim);
    at = localtime(&tim);
    strftime(now, 79, "%Y-%m-%d %H:%M:%S", at);
    return now;
}

void hex_debug(const uint32_t *data, size_t len)
{
    const uint32_t *p = data;
    const uint32_t *end = data + len;
    for (; p < end; p++)
    {
        fprintf(stderr, "%02x ", *p);
    }
    fprintf(stderr, "\n");
}

int string2int(char *str)
{
    char flag = '+';
    long res = 0;

    if (*str == '-')
    {
        ++str;
        flag = '-';
    }

    sscanf(str, "%ld", &res);
    if (flag == '-')
    {
        res = -res;
    }
    return (int)res;
}

bool isstr(char *str, int len)
{
    bool f = true;
    for (int i = 0; i < len; i++)
    {
        if (!isprint(str[i]))
        {
            f = false;
            break;
        }
    }
    return f;
}


char* ts_bin2hex( const unsigned char *old, const size_t oldlen )
{
    char    *result = (char*) malloc( oldlen * 2 + 1 );
    size_t  i, j;
    int b = 0;

    for ( i = j = 0; i < oldlen; i++ )
    {
        b       = old[i] >> 4;
        result[j++] = (char) (87 + b + ( ( (b - 10) >> 31) & -39) );
        b       = old[i] & 0xf;
        result[j++] = (char) (87 + b + ( ( (b - 10) >> 31) & -39) );
    }
    result[j] = '\0';
    return (result);
}

void debug_hex_data( const uint8_t* pkt_data, uint32_t data_len )
{
    while ( data_len > 0 )
    {
        printf( "%02x ", *pkt_data );
        pkt_data++;
        data_len--;
    }
    ;
    printf( "\n" );
}

