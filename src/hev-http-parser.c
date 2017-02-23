/*
 ============================================================================
 Name        : hev-http-parser.h
 Author      : Nginx, Inc.
               Heiher <r@hev.cc>
 Copyright   : Copyright (c) Igor Sysoev
               Copyright (c) Nginx, Inc.
 Description : HTTP Parser
 ============================================================================
 */

#include <string.h>

#include <hev-memory-allocator.h>

#include "hev-http-parser.h"

#define CR '\r'
#define LF '\n'

#define HEV_MAX_OFF_T_VALUE 9223372036854775807

static unsigned int usual[] = {
    0xffffdbfe, /* 1111 1111 1111 1111  1101 1011 1111 1110 */

    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
    0x7fff37d6, /* 0111 1111 1111 1111  0011 0111 1101 0110 */

    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff /* 1111 1111 1111 1111  1111 1111 1111 1111 */
};

#define str3_cmp(m, c0, c1, c2, c3) m[0] == c0 &&m[1] == c1 &&m[2] == c2

#define str3Ocmp(m, c0, c1, c2, c3) m[0] == c0 &&m[2] == c2 &&m[3] == c3

#define str4cmp(m, c0, c1, c2, c3) \
    m[0] == c0 &&m[1] == c1 &&m[2] == c2 &&m[3] == c3

#define str5cmp(m, c0, c1, c2, c3, c4) \
    m[0] == c0 &&m[1] == c1 &&m[2] == c2 &&m[3] == c3 &&m[4] == c4

#define str6cmp(m, c0, c1, c2, c3, c4, c5) \
    m[0] == c0 &&m[1] == c1 &&m[2] == c2 &&m[3] == c3 &&m[4] == c4 &&m[5] == c5

#define str7_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                          \
    m[0] == c0 &&m[1] == c1 &&m[2] == c2 &&m[3] == c3 &&m[4] == c4 &&m[5] == \
        c5 &&m[6] == c6

#define str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                           \
    m[0] == c0 &&m[1] == c1 &&m[2] == c2 &&m[3] == c3 &&m[4] == c4 &&m[5] == \
        c5 &&m[6] == c6 &&m[7] == c7

#define str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                       \
    m[0] == c0 &&m[1] == c1 &&m[2] == c2 &&m[3] == c3 &&m[4] == c4 &&m[5] == \
        c5 &&m[6] == c6 &&m[7] == c7 &&m[8] == c8

HevHttpBuffer *
hev_http_buffer_new (unsigned int size)
{
    HevHttpBuffer *buffer;

    buffer = hev_malloc (sizeof (HevHttpBuffer) + size);
    if (buffer) {
        buffer->pos = buffer->data;
        buffer->last = buffer->data;
        buffer->size = size;
    }

    return buffer;
}

void
hev_http_buffer_destroy (HevHttpBuffer *buffer)
{
    hev_free (buffer);
}

void
hev_http_buffer_reset (HevHttpBuffer *buffer)
{
    if (buffer->pos != buffer->last)
        memmove (buffer->data, buffer->pos, buffer->last - buffer->pos);

    buffer->last -= buffer->pos - buffer->data;
    buffer->pos = buffer->data;
}

int
hev_http_buffer_write (HevHttpBuffer *buffer, const void *data,
                       unsigned int len)
{
    unsigned int size;

    size = buffer->data + buffer->size - buffer->last;
    if (len > size)
        len = size;

    memcpy (buffer->last, data, len);
    buffer->last += len;

    return len;
}

HevHttpParser *
hev_http_parser_new (int max_headers)
{
    HevHttpParser *parser;

    parser = hev_malloc (sizeof (HevHttpParser) +
                         sizeof (HevHttpHeader) * max_headers);
    if (parser) {
        parser->code = 0;
        parser->state = 0;
        parser->header_used = 0;
        parser->max_headers = max_headers;
    }

    return parser;
}

void
hev_http_parser_destroy (HevHttpParser *parser)
{
    hev_free (parser);
}

int
hev_http_parser_parse_request_line (HevHttpParser *parser,
                                    HevHttpBuffer *buffer)
{
    enum
    {
        sw_start = 0,
        sw_method,
        sw_spaces_before_uri,
        sw_schema,
        sw_schema_slash,
        sw_schema_slash_slash,
        sw_host_start,
        sw_host,
        sw_host_end,
        sw_host_ip_literal,
        sw_port,
        sw_host_http_09,
        sw_after_slash_in_uri,
        sw_check_uri,
        sw_check_uri_http_09,
        sw_uri,
        sw_http_09,
        sw_http_H,
        sw_http_HT,
        sw_http_HTT,
        sw_http_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_spaces_after_digit,
        sw_almost_done
    } state;
    unsigned char c, ch;
    const unsigned char *p, *m;

    state = parser->state;

    for (p = buffer->pos; p < buffer->last; p++) {
        ch = *p;

        switch (state) {
        /* HTTP methods: GET, HEAD, POST */
        case sw_start:
            parser->header_used = 0;
            parser->method = (const char *)p;

            if (ch == CR || ch == LF)
                break;

            if ((ch < 'A' || ch > 'Z') && ch != '_' && ch != '-')
                return HEV_HTTP_PARSER_ERROR;

            state = sw_method;
            break;
        case sw_method:
            if (ch == ' ') {
                m = (const unsigned char *)parser->method;
                parser->method_len = p - m;

                switch (parser->method_len) {
                case 3:
                    if (str3_cmp (m, 'G', 'E', 'T', ' '))
                        break;
                    if (str3_cmp (m, 'P', 'U', 'T', ' '))
                        break;
                    return HEV_HTTP_PARSER_ERROR;
                case 4:
                    if (m[1] == 'O') {
                        if (str3Ocmp (m, 'P', 'O', 'S', 'T'))
                            break;
                        if (str3Ocmp (m, 'C', 'O', 'P', 'Y'))
                            break;
                        if (str3Ocmp (m, 'M', 'O', 'V', 'E'))
                            break;
                        if (str3Ocmp (m, 'L', 'O', 'C', 'K'))
                            break;
                    } else {
                        if (str4cmp (m, 'H', 'E', 'A', 'D'))
                            break;
                    }
                    return HEV_HTTP_PARSER_ERROR;
                case 5:
                    if (str5cmp (m, 'M', 'K', 'C', 'O', 'L'))
                        break;
                    if (str5cmp (m, 'P', 'A', 'T', 'C', 'H'))
                        break;
                    if (str5cmp (m, 'T', 'R', 'A', 'C', 'E'))
                        break;
                    return HEV_HTTP_PARSER_ERROR;
                case 6:
                    if (str6cmp (m, 'D', 'E', 'L', 'E', 'T', 'E'))
                        break;
                    if (str6cmp (m, 'U', 'N', 'L', 'O', 'C', 'K'))
                        break;
                    return HEV_HTTP_PARSER_ERROR;
                case 7:
                    if (str7_cmp (m, 'O', 'P', 'T', 'I', 'O', 'N', 'S', ' '))
                        break;
                    return HEV_HTTP_PARSER_ERROR;
                case 8:
                    if (str8cmp (m, 'P', 'R', 'O', 'P', 'F', 'I', 'N', 'D'))
                        break;
                    return HEV_HTTP_PARSER_ERROR;
                case 9:
                    if (str9cmp (m, 'P', 'R', 'O', 'P', 'P', 'A', 'T', 'C',
                                 'H'))
                        break;
                default:
                    return HEV_HTTP_PARSER_ERROR;
                }

                state = sw_spaces_before_uri;
                break;
            }

            if ((ch < 'A' || ch > 'Z') && ch != '_' && ch != '-')
                return HEV_HTTP_PARSER_ERROR;
            break;
        /* space* before URI */
        case sw_spaces_before_uri:
            if (ch == '/') {
                parser->uri = (const char *)p;
                state = sw_after_slash_in_uri;
                break;
            }

            c = (unsigned char)(ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                parser->schema = (const char *)p;
                state = sw_schema;
                break;
            }

            switch (ch) {
            case ' ':
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        case sw_schema:
            c = (unsigned char)(ch | 0x20);
            if (c >= 'a' && c <= 'z')
                break;

            if ((ch >= '0' && ch <= '9') || ch == '+' || ch == '-' || ch == '.')
                break;

            switch (ch) {
            case ':':
                parser->schema_len = (char *)p - parser->schema;
                ;
                state = sw_schema_slash;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        case sw_schema_slash:
            switch (ch) {
            case '/':
                state = sw_schema_slash_slash;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        case sw_schema_slash_slash:
            switch (ch) {
            case '/':
                state = sw_host_start;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        case sw_host_start:
            parser->host = (const char *)p;

            if (ch == '[') {
                state = sw_host_ip_literal;
                break;
            }

            state = sw_host;
            /* fall through */
        case sw_host:
            c = (unsigned char)(ch | 0x20);
            if (c >= 'a' && c <= 'z')
                break;

            if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-')
                break;
            /* fall through */
        case sw_host_end:
            parser->host_len = (char *)p - parser->host;

            switch (ch) {
            case ':':
                state = sw_port;
                break;
            case '/':
                parser->uri = (const char *)p;
                state = sw_after_slash_in_uri;
                break;
            case ' ':
                /*
                 * use single "/" from request line to preserve pointers,
                 * if request line will be copied to large client buffer
                 */
                parser->uri = parser->schema + parser->schema_len + 1;
                parser->uri_len = 1;
                state = sw_host_http_09;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        case sw_host_ip_literal:
            if (ch >= '0' && ch <= '9')
                break;

            c = (unsigned char)(ch | 0x20);
            if (c >= 'a' && c <= 'z')
                break;

            switch (ch) {
            case ':':
                break;
            case ']':
                state = sw_host_end;
                break;
            case '-':
            case '.':
            case '_':
            case '~':
                /* unreserved */
                break;
            case '!':
            case '$':
            case '&':
            case '\'':
            case '(':
            case ')':
            case '*':
            case '+':
            case ',':
            case ';':
            case '=':
                /* sub-delims */
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        case sw_port:
            if (ch >= '0' && ch <= '9')
                break;

            switch (ch) {
            case '/':
                parser->host_len = (char *)p - parser->host;
                parser->uri = (const char *)p;
                state = sw_after_slash_in_uri;
                break;
            case ' ':
                parser->host_len = (char *)p - parser->host;
                /*
                 * use single "/" from request line to preserve pointers,
                 * if request line will be copied to large client buffer
                 */
                parser->uri = parser->schema + parser->schema_len + 1;
                parser->uri_len = 1;
                state = sw_host_http_09;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        /* space+ after "http://host[:port] " */
        case sw_host_http_09:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            case 'H':
                parser->version = (const char *)p;
                state = sw_http_H;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        /* check "/.", "//", "%", and "\" (Win32) in URI */
        case sw_after_slash_in_uri:
            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                state = sw_check_uri;
                break;
            }

            switch (ch) {
            case ' ':
                parser->uri_len = (char *)p - parser->uri;
                state = sw_check_uri_http_09;
                break;
            case CR:
                parser->uri_len = (char *)p - parser->uri;
                state = sw_almost_done;
                break;
            case LF:
                parser->uri_len = (char *)p - parser->uri;
                goto done;
            case '.':
            case '%':
            case '/':
            case '?':
            case '#':
                state = sw_uri;
                break;
            case '+':
                break;
            case '\0':
                return HEV_HTTP_PARSER_ERROR;
            default:
                state = sw_check_uri;
                break;
            }
            break;
        /* check "/", "%" and "\" (Win32) in URI */
        case sw_check_uri:
            if (usual[ch >> 5] & (1U << (ch & 0x1f)))
                break;

            switch (ch) {
            case '/':
                state = sw_after_slash_in_uri;
                break;
            case '.':
                break;
            case ' ':
                parser->uri_len = (char *)p - parser->uri;
                state = sw_check_uri_http_09;
                break;
            case CR:
                parser->uri_len = (char *)p - parser->uri;
                state = sw_almost_done;
                break;
            case LF:
                parser->uri_len = (char *)p - parser->uri;
                goto done;
            case '%':
            case '?':
            case '#':
                state = sw_uri;
                break;
            case '+':
                break;
            case '\0':
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        /* space+ after URI */
        case sw_check_uri_http_09:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            case 'H':
                parser->version = (const char *)p;
                state = sw_http_H;
                break;
            default:
                state = sw_check_uri;
                p--;
                break;
            }
            break;
        /* URI */
        case sw_uri:
            if (usual[ch >> 5] & (1U << (ch & 0x1f)))
                break;

            switch (ch) {
            case ' ':
                parser->uri_len = (char *)p - parser->uri;
                state = sw_http_09;
                break;
            case CR:
                parser->uri_len = (char *)p - parser->uri;
                state = sw_almost_done;
                break;
            case LF:
                parser->uri_len = (char *)p - parser->uri;
                goto done;
            case '#':
                break;
            case '\0':
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        /* space+ after URI */
        case sw_http_09:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            case 'H':
                parser->version = (const char *)p;
                state = sw_http_H;
                break;
            default:
                state = sw_uri;
                p--;
                break;
            }
            break;
        case sw_http_H:
            switch (ch) {
            case 'T':
                state = sw_http_HT;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        case sw_http_HT:
            switch (ch) {
            case 'T':
                state = sw_http_HTT;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        case sw_http_HTT:
            switch (ch) {
            case 'P':
                state = sw_http_HTTP;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        case sw_http_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        /* first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9')
                return HEV_HTTP_PARSER_ERROR;

            state = sw_major_digit;
            break;
        /* major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9')
                return HEV_HTTP_PARSER_ERROR;

            break;
        /* first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9')
                return HEV_HTTP_PARSER_ERROR;

            state = sw_minor_digit;
            break;
        /* minor HTTP version or end of request line */
        case sw_minor_digit:
            if (ch == CR) {
                parser->version_len = (char *)p - parser->version;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                parser->version_len = (char *)p - parser->version;
                goto done;
            }

            if (ch == ' ') {
                parser->version_len = (char *)p - parser->version;
                state = sw_spaces_after_digit;
                break;
            }

            if (ch < '0' || ch > '9')
                return HEV_HTTP_PARSER_ERROR;
            break;
        case sw_spaces_after_digit:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        /* end of request line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
        }
    }

    buffer->pos = (unsigned char *)p;
    parser->state = state;
    return HEV_HTTP_PARSER_AGAIN;

done:
    buffer->pos = (unsigned char *)(p + 1);
    parser->state = sw_start;
    return HEV_HTTP_PARSER_OK;
}

int
hev_http_parser_parse_status_line (HevHttpParser *parser, HevHttpBuffer *buffer)
{
    enum
    {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;
    unsigned char ch;
    const unsigned char *p;

    state = parser->state;

    for (p = buffer->pos; p < buffer->last; p++) {
        ch = *p;

        switch (state) {
        /* "HTTP/" */
        case sw_start:
            switch (ch) {
            case 'H':
                parser->version = (const char *)p;
                parser->header_used = 0;
                parser->status_len = 0;
                parser->code = 0;
                state = sw_H;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9')
                return HEV_HTTP_PARSER_ERROR;

            state = sw_major_digit;
            break;
        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9')
                return HEV_HTTP_PARSER_ERROR;
            break;
        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9')
                return HEV_HTTP_PARSER_ERROR;

            state = sw_minor_digit;
            break;
        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                parser->version_len = (char *)p - parser->version;
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9')
                return HEV_HTTP_PARSER_ERROR;
            break;
        /* HTTP status code */
        case sw_status:
            if (ch == ' ')
                break;

            if (ch < '0' || ch > '9')
                return HEV_HTTP_PARSER_ERROR;

            parser->code = parser->code * 10 + (ch - '0');

            if (++parser->status_len == 3) {
                state = sw_space_after_status;
                parser->status = (const char *)(p - 2);
            }
            break;
        /* space or end of line */
        case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case '.': /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                parser->status_len = (char *)p - parser->status;
                state = sw_almost_done;
                break;
            case LF:
                parser->status_len = (char *)p - parser->status;
                goto done;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                parser->status_len = (char *)p - parser->status;
                state = sw_almost_done;
                break;
            case LF:
                parser->status_len = (char *)p - parser->status;
                goto done;
            }
            break;
        /* end of status line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
        }
    }

    buffer->pos = (unsigned char *)p;
    parser->state = state;
    return HEV_HTTP_PARSER_AGAIN;

done:
    buffer->pos = (unsigned char *)(p + 1);
    parser->state = sw_start;
    return HEV_HTTP_PARSER_OK;
}

int
hev_http_parser_parse_header_line (HevHttpParser *parser, HevHttpBuffer *buffer)
{
    enum
    {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done
    } state;
    unsigned int i;
    unsigned char c, ch;
    const unsigned char *p;
    HevHttpHeader *header;

    /* the last '\0' is not needed because string is zero terminated */
    static unsigned char lowcase[] =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0"
        "0123456789\0\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    state = parser->state;
    i = parser->lowcase_idx;
    header = &parser->headers[parser->header_used];

    if (parser->header_used >= parser->max_headers)
        return HEV_HTTP_PARSER_ERROR;

    for (p = buffer->pos; p < buffer->last; p++) {
        ch = *p;

        switch (state) {
        /* first char */
        case sw_start:
            header->name = (const char *)p;

            switch (ch) {
            case CR:
                state = sw_header_almost_done;
                break;
            case LF:
                goto header_done;
            default:
                state = sw_name;
                c = lowcase[ch];

                if (c) {
                    header->lowcase_name[0] = c;
                    i = 1;
                    break;
                }

                if (ch == '_') {
                    header->lowcase_name[0] = ch;
                    i = 1;
                    break;
                }

                if (ch == '\0')
                    return HEV_HTTP_PARSER_ERROR;

                i = 0;
                break;
            }
            break;
        /* header name */
        case sw_name:
            c = lowcase[ch];

            if (c) {
                header->lowcase_name[i++] = c;
                i &= (HEV_HTTP_LC_HEADER_LEN - 1);
                break;
            }

            if (ch == '_') {
                header->lowcase_name[i++] = ch;
                i &= (HEV_HTTP_LC_HEADER_LEN - 1);
                break;
            }

            if (ch == ':') {
                header->lowcase_name[i] = '\0';
                header->name_len = (char *)p - header->name;
                state = sw_space_before_value;
                break;
            }

            if (ch == CR) {
                header->lowcase_name[i] = '\0';
                header->name_len = (char *)p - header->name;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                header->lowcase_name[i] = '\0';
                header->name_len = (char *)p - header->name;
                goto done;
            }

            if (ch == '\0')
                return HEV_HTTP_PARSER_ERROR;

            break;
        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            case '\0':
                return HEV_HTTP_PARSER_ERROR;
            default:
                header->value = (const char *)p;
                state = sw_value;
                break;
            }
            break;
        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                header->value_len = (char *)p - header->value;
                state = sw_space_after_value;
                break;
            case CR:
                header->value_len = (char *)p - header->value;
                state = sw_almost_done;
                break;
            case LF:
                header->value_len = (char *)p - header->value;
                goto done;
            case '\0':
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            case '\0':
                return HEV_HTTP_PARSER_ERROR;
            default:
                state = sw_value;
                break;
            }
            break;
        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            case CR:
                break;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
            break;
        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return HEV_HTTP_PARSER_ERROR;
            }
        }
    }

    buffer->pos = (unsigned char *)p;
    parser->state = state;
    parser->lowcase_idx = i;
    return HEV_HTTP_PARSER_AGAIN;

done:
    buffer->pos = (unsigned char *)(p + 1);
    parser->state = sw_start;
    parser->lowcase_idx = i;
    if (header->name_len)
        parser->header_used++;
    return HEV_HTTP_PARSER_OK;

header_done:
    buffer->pos = (unsigned char *)(p + 1);
    parser->state = sw_start;
    return HEV_HTTP_PARSER_DONE;
}

int
hev_http_parser_parse_chunked (HevHttpParser *parser, HevHttpBuffer *buffer)
{
    enum
    {
        sw_chunk_start = 0,
        sw_chunk_size,
        sw_chunk_extension,
        sw_chunk_extension_almost_done,
        sw_chunk_data,
        sw_after_data,
        sw_after_data_almost_done,
        sw_last_chunk_extension,
        sw_last_chunk_extension_almost_done,
        sw_trailer,
        sw_trailer_almost_done,
        sw_trailer_header,
        sw_trailer_header_almost_done
    } state;
    int res;
    unsigned char c, ch;
    const unsigned char *pos;

    res = HEV_HTTP_PARSER_AGAIN;
    state = parser->state;

    if (state == sw_chunk_data && parser->chunk_size == 0)
        state = sw_after_data;

    for (pos = buffer->pos; pos < buffer->last; pos++) {
        ch = *pos;

        switch (state) {
        case sw_chunk_start:
            if (ch >= '0' && ch <= '9') {
                state = sw_chunk_size;
                parser->chunk_size = ch - '0';
                break;
            }

            c = (unsigned char)(ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                state = sw_chunk_size;
                parser->chunk_size = c - 'a' + 10;
                break;
            }
            goto invalid;
        case sw_chunk_size:
            if (parser->chunk_size > HEV_MAX_OFF_T_VALUE / 16)
                goto invalid;

            if (ch >= '0' && ch <= '9') {
                parser->chunk_size = parser->chunk_size * 16 + (ch - '0');
                break;
            }

            c = (unsigned char)(ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                parser->chunk_size = parser->chunk_size * 16 + (c - 'a' + 10);
                break;
            }

            if (parser->chunk_size == 0) {
                switch (ch) {
                case CR:
                    state = sw_last_chunk_extension_almost_done;
                    break;
                case LF:
                    state = sw_trailer;
                    break;
                case ';':
                case ' ':
                case '\t':
                    state = sw_last_chunk_extension;
                    break;
                default:
                    goto invalid;
                }
                break;
            }

            switch (ch) {
            case CR:
                state = sw_chunk_extension_almost_done;
                break;
            case LF:
                state = sw_chunk_data;
                break;
            case ';':
            case ' ':
            case '\t':
                state = sw_chunk_extension;
                break;
            default:
                goto invalid;
            }
            break;
        case sw_chunk_extension:
            switch (ch) {
            case CR:
                state = sw_chunk_extension_almost_done;
                break;
            case LF:
                state = sw_chunk_data;
            }
            break;
        case sw_chunk_extension_almost_done:
            if (ch == LF) {
                state = sw_chunk_data;
                break;
            }
            goto invalid;
        case sw_chunk_data:
            res = HEV_HTTP_PARSER_OK;
            goto data;
        case sw_after_data:
            switch (ch) {
            case CR:
                state = sw_after_data_almost_done;
                break;
            case LF:
                state = sw_chunk_start;
                break;
            default:
                goto invalid;
            }
            break;
        case sw_after_data_almost_done:
            if (ch == LF) {
                state = sw_chunk_start;
                break;
            }
            goto invalid;
        case sw_last_chunk_extension:
            switch (ch) {
            case CR:
                state = sw_last_chunk_extension_almost_done;
                break;
            case LF:
                state = sw_trailer;
            }
            break;
        case sw_last_chunk_extension_almost_done:
            if (ch == LF) {
                state = sw_trailer;
                break;
            }
            goto invalid;
        case sw_trailer:
            switch (ch) {
            case CR:
                state = sw_trailer_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_trailer_header;
            }
            break;
        case sw_trailer_almost_done:
            if (ch == LF)
                goto done;
            goto invalid;
        case sw_trailer_header:
            switch (ch) {
            case CR:
                state = sw_trailer_header_almost_done;
                break;
            case LF:
                state = sw_trailer;
            }
            break;
        case sw_trailer_header_almost_done:
            if (ch == LF) {
                state = sw_trailer;
                break;
            }
            goto invalid;
        }
    }

data:
    parser->state = state;
    buffer->pos = (unsigned char *)pos;

    if (parser->chunk_size > HEV_MAX_OFF_T_VALUE - 5)
        goto invalid;

    return res;

done:
    parser->state = 0;
    buffer->pos = (unsigned char *)(pos + 1);
    return HEV_HTTP_PARSER_DONE;

invalid:
    return HEV_HTTP_PARSER_ERROR;
}
