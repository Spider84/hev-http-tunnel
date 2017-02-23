/*
 ============================================================================
 Name        : hev-http-parser.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 everyone.
 Description : HTTP Parser
 ============================================================================
 */

#ifndef __HEV_HTTP_PARSER_H__
#define __HEV_HTTP_PARSER_H__

#ifdef __cplusplus
extern "C" {
#endif

#define HEV_HTTP_PARSER_OK 0
#define HEV_HTTP_PARSER_DONE 1
#define HEV_HTTP_PARSER_ERROR -1
#define HEV_HTTP_PARSER_AGAIN -2

#define HEV_HTTP_LC_HEADER_LEN 32

typedef struct _HevHttpBuffer HevHttpBuffer;
typedef struct _HevHttpHeader HevHttpHeader;
typedef struct _HevHttpParser HevHttpParser;

struct _HevHttpBuffer
{
    /* public */
    unsigned char *pos;
    unsigned char *last;

    unsigned int size;
    unsigned char data[0];
};

struct _HevHttpHeader
{
    /* public */
    char lowcase_name[HEV_HTTP_LC_HEADER_LEN];
    const char *name;
    const char *value;
    unsigned int name_len;
    unsigned int value_len;
};

struct _HevHttpParser
{
    /* private */
    int state;
    int max_headers;
    unsigned int lowcase_idx;

    /* public */
    int header_used;
    unsigned int chunk_size;

    unsigned int method_len;
    unsigned int schema_len;
    unsigned int host_len;
    unsigned int uri_len;
    unsigned int version_len;
    unsigned int status_len;
    unsigned int code;

    const char *method;
    const char *schema;
    const char *host;
    const char *uri;
    const char *version;
    const char *status;

    HevHttpHeader headers[0];
};

HevHttpBuffer *hev_http_buffer_new (unsigned int size);
void hev_http_buffer_destroy (HevHttpBuffer *buffer);

void hev_http_buffer_reset (HevHttpBuffer *buffer);
int hev_http_buffer_write (HevHttpBuffer *buffer, const void *data,
                           unsigned int len);

HevHttpParser *hev_http_parser_new (int max_headers);
void hev_http_parser_destroy (HevHttpParser *parser);

int hev_http_parser_parse_request_line (HevHttpParser *parser,
                                        HevHttpBuffer *buffer);
int hev_http_parser_parse_status_line (HevHttpParser *parser,
                                       HevHttpBuffer *buffer);
int hev_http_parser_parse_header_line (HevHttpParser *parser,
                                       HevHttpBuffer *buffer);
int hev_http_parser_parse_chunked (HevHttpParser *parser,
                                   HevHttpBuffer *buffer);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_HTTP_PARSER_H__ */
