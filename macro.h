/*************************************************************************
    > File Name: macro.h
    > Author: jige003
 ************************************************************************/

#ifndef _MACRO_H
#define _MACRO_H

#if defined(__cplusplus)
#define __BEGIN_DECLS   extern "C" {
#define __END_DECLS     }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif

__BEGIN_DECLS

#define dbg( fmt, ... ) \
    do { \
        if ( debug ) { \
            fprintf( stderr, "\033[0;32m[+] " fmt, ## __VA_ARGS__ ); \
            fprintf( stderr, "\033[0m" ); \
        } \
    } while (0);


#define imalloc(type, var)\
        var = (type*) malloc(sizeof(type));\
        memset(var, 0, sizeof(type));

#define XFREE( ptr ) \
    do { \
        if ( !(ptr) ) { \
            free( (void*) (ptr) ); \
            ptr = NULL;\
        } \
    } while (0);

#define memcpy_str_x( s, ptr, buflen ) \
    do { \
        if ( buflen <= 0 ) { \
            dbg( "return false by:%s\n", #s ); \
            return(false); \
        } \
        s = get_str( &ptr, &buflen ); \
    } while (0);

#define memcpy_int_x( s, ptr, size, buflen ) \
    do { \
        if ( buflen < size ) { \
            dbg( "return false by:%s\n", #s ); \
            return(false); \
        } \
        memcpy( (void*) &s, (void*) ptr, size ); \
        (ptr)   += size; \
        buflen  -= size; \
    } while (0);

#define STMT_BUFFER_STR_PARSER( str_type, dbuf, buf, p, s_len, data_len ) \
case str_type: \
    s_len = *(p++); \
    memcpy( buf, p, s_len ); \
    p       += s_len; \
    data_len    -= s_len; \
    dbg( "s_len:%d buf:%s\n", s_len, buf ); \
    dbuf = buf; \
    break;

#define STMT_BUFFER_INTX_PARSER( str_type, dbuf, buf, p, intx, size, data_len, fmt ) \
case str_type: \
    memcpy( &intx, p, size ); \
    p       += size; \
    data_len    -= size; \
    sprintf( buf, fmt, intx ); \
    dbg( "intx buf:%s\n", buf ); \
    dbuf = buf; \
    break;

__END_DECLS

#endif
