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

#include <stdint.h>

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
    uint8_t *pos;
    uint8_t *last;

    size_t size;
    uint8_t data[0];
};

struct _HevHttpHeader
{
    /* public */
    char lowcase_name[HEV_HTTP_LC_HEADER_LEN];
    const char *name;
    const char *value;
    uint32_t name_len;
    uint32_t value_len;
};

struct _HevHttpParser
{
    /* private */
    int state;
    uint32_t max_headers;
    uint32_t lowcase_idx;

    /* public */
    uint32_t header_used;
    uint64_t chunk_size;

    uint32_t method_len;
    uint32_t schema_len;
    uint32_t host_len;
    uint32_t uri_len;
    uint32_t version_len;
    uint32_t status_len;
    uint32_t code;

    const char *method;
    const char *schema;
    const char *host;
    const char *uri;
    const char *version;
    const char *status;

    HevHttpHeader headers[0];
};

HevHttpBuffer *hev_http_buffer_new (size_t size);
void hev_http_buffer_destroy (HevHttpBuffer *buffer);

void hev_http_buffer_reset (HevHttpBuffer *buffer);
int hev_http_buffer_write (HevHttpBuffer *buffer, const void *data, size_t len);

HevHttpParser *hev_http_parser_new (uint32_t max_headers);
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
