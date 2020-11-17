/*
 ============================================================================
 Name        : hev-http-session.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 Everyone.
 Description : Http Session
 ============================================================================
 */

#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <hev-task.h>
#include <hev-task-mutex.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-memory-allocator.h>

#include "hev-config.h"
#include "hev-logger.h"
#include "hev-http-parser.h"

#include "hev-http-session.h"

#define SESSION_HP (10)
#define SADDR_SIZE (64)
#define QUEUE_SIZE (128)
#define BUFFER_SIZE (8192)
#define TASK_STACK_SIZE (20480)

enum
{
    STEP_NULL,
    STEP_CONNECT_PROXY,
    STEP_FORWARD_HTTP,
    STEP_FORWARD_DNS,
    STEP_CONNECT_ORIG,
    STEP_SPLICE_STREAM,
    STEP_CLOSE_SESSION,
};

struct _HevHttpSession
{
    HevHttpSessionBase base;

    int remote_fd;
    int ref_count;

    union
    {
        struct tcp_pcb *tcp;
        struct udp_pcb *udp;
    };

    union
    {
        struct
        {
            ip_addr_t addr;
            u16_t port;
        };

        struct
        {
            char host[SADDR_SIZE];
            uint16_t host_len;
        };
    };

    char *saddr;
    struct pbuf *query;
    struct pbuf *queue;
    HevTaskMutex *mutex;
    HevHttpSessionCloseNotify notify;
};

static void hev_http_session_task_entry (void *data);
static err_t tcp_recv_handler (void *arg, struct tcp_pcb *pcb, struct pbuf *p,
                               err_t err);
static err_t tcp_sent_handler (void *arg, struct tcp_pcb *pcb, u16_t len);
static void tcp_err_handler (void *arg, err_t err);

static HevHttpSession *
hev_http_session_new (HevTaskMutex *mutex, HevHttpSessionCloseNotify notify)
{
    HevHttpSession *self;
    HevTask *task;

    self = hev_malloc (sizeof (HevHttpSession));
    if (!self)
        return NULL;

    __builtin_bzero (self, sizeof (HevHttpSession));
    self->base.hp = SESSION_HP;

    self->ref_count = 1;
    self->remote_fd = -1;
    self->notify = notify;
    self->mutex = mutex;

    if (LOG_ON ())
        self->saddr = hev_malloc (SADDR_SIZE);

    task = hev_task_new (TASK_STACK_SIZE);
    if (!task) {
        hev_free (self);
        return NULL;
    }

    self->base.task = task;
    hev_task_set_priority (task, 9);

    return self;
}

HevHttpSession *
hev_http_session_new_tcp (struct tcp_pcb *pcb, HevTaskMutex *mutex,
                          HevHttpSessionCloseNotify notify)
{
    HevHttpSession *self;
    const char *sa;
    char buf[64];
    int port;

    self = hev_http_session_new (mutex, notify);
    if (!self)
        return NULL;

    self->tcp = pcb;
    port = pcb->local_port;
    sa = ipaddr_ntoa_r (&pcb->local_ip, buf, sizeof (buf));
    if (pcb->local_ip.type == IPADDR_TYPE_V6)
        self->host_len = snprintf (self->host, SADDR_SIZE, "[%s]:%u", sa, port);
    else
        self->host_len = snprintf (self->host, SADDR_SIZE, "%s:%u", sa, port);

    tcp_arg (pcb, self);
    tcp_recv (pcb, tcp_recv_handler);
    tcp_sent (pcb, tcp_sent_handler);
    tcp_err (pcb, tcp_err_handler);

    if (LOG_ON ()) {
        port = pcb->remote_port;

        sa = ipaddr_ntoa_r (&pcb->remote_ip, buf, sizeof (buf));
        if (self->saddr)
            snprintf (self->saddr, SADDR_SIZE, "[%s]:%u", sa, port);

        port = pcb->local_port;
        sa = ipaddr_ntoa_r (&pcb->local_ip, buf, sizeof (buf));
        LOG_I ("Session %s: created TCP -> [%s]:%u", self->saddr, sa, port);
    }

    return self;
}

HevHttpSession *
hev_http_session_new_dns (struct udp_pcb *pcb, struct pbuf *p,
                          const ip_addr_t *addr, u16_t port,
                          HevTaskMutex *mutex, HevHttpSessionCloseNotify notify)
{
    HevHttpSession *self;

    self = hev_http_session_new (mutex, notify);
    if (!self)
        return NULL;

    self->udp = pcb;
    self->query = p;
    self->port = port;
    __builtin_memcpy (&self->addr, addr, sizeof (ip_addr_t));

    if (LOG_ON ()) {
        char buf[64];
        const char *sa;

        sa = ipaddr_ntoa_r (addr, buf, sizeof (buf));
        if (self->saddr)
            snprintf (self->saddr, SADDR_SIZE, "[%s]:%u", sa, port);
        LOG_I ("Session %s: created DNS", self->saddr);
    }

    return self;
}

HevHttpSession *
hev_http_session_ref (HevHttpSession *self)
{
    self->ref_count++;

    return self;
}

void
hev_http_session_unref (HevHttpSession *self)
{
    self->ref_count--;
    if (self->ref_count)
        return;

    hev_free (self);
}

void
hev_http_session_run (HevHttpSession *self)
{
    hev_task_run (self->base.task, hev_http_session_task_entry, self);
}

static err_t
tcp_recv_handler (void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    HevHttpSession *self = arg;

    if ((err != ERR_OK) || !p) {
        self->base.hp = 0;
        goto exit;
    }

    if (!self->queue)
        self->queue = p;
    else
        pbuf_cat (self->queue, p);

    tcp_recved (pcb, p->tot_len);

exit:
    hev_task_wakeup (self->base.task);
    return ERR_OK;
}

static err_t
tcp_sent_handler (void *arg, struct tcp_pcb *pcb, u16_t len)
{
    HevHttpSession *self = arg;

    hev_task_wakeup (self->base.task);
    return ERR_OK;
}

static void
tcp_err_handler (void *arg, err_t err)
{
    HevHttpSession *self = arg;

    self->tcp = NULL;
    self->base.hp = 0;
    hev_task_wakeup (self->base.task);
}

static int
task_io_yielder (HevTaskYieldType type, void *data)
{
    HevHttpSession *self = data;

    self->base.hp = SESSION_HP;
    hev_task_yield (type);
    return (self->base.hp > 0) ? 0 : -1;
}

static int
http_connect_proxy (HevHttpSession *self)
{
    HevConfigServer *srv;
    int res;

    res = hev_task_io_socket_socket (AF_INET6, SOCK_STREAM, 0);
    if (res < 0) {
        LOG_W ("Session %s: create remote socket failed!", self->saddr);
        return STEP_CLOSE_SESSION;
    }

    self->remote_fd = res;
    hev_task_add_fd (hev_task_self (), self->remote_fd, POLLIN | POLLOUT);

    srv = hev_config_get_server (hev_config_get_perfect_server ());
    res = hev_task_io_socket_connect (self->remote_fd,
                                      (struct sockaddr *)srv->addr,
                                      srv->addr_len, task_io_yielder, self);
    if (res < 0) {
        LOG_W ("Session %s: connect remote server failed!", self->saddr);
        return STEP_CLOSE_SESSION;
    }

    return self->query ? STEP_CONNECT_ORIG : STEP_FORWARD_HTTP;
}

static int
http_recv_pb (HevHttpSession *self, HevHttpBuffer *buffer)
{
    size_t len;

    while (!self->queue) {
        if (task_io_yielder (HEV_TASK_WAITIO, self) < 0)
            return -1;
    }

    len = buffer->size - (buffer->last - buffer->data);
    if (!len)
        return -1;

    hev_task_mutex_lock (self->mutex);
    len = pbuf_copy_partial (self->queue, buffer->last, len, 0);
    self->queue = pbuf_free_header (self->queue, len);
    hev_task_mutex_unlock (self->mutex);

    buffer->last += len;
    return 0;
}

static int
http_send_pb (HevHttpSession *self, const void *data, size_t len)
{
    while (len) {
        err_t err = ERR_OK;
        size_t size;

        if (!self->tcp)
            return -1;

        if (!(size = tcp_sndbuf (self->tcp))) {
            if (task_io_yielder (HEV_TASK_WAITIO, self) < 0)
                return -1;
            continue;
        }

        if (size > len)
            size = len;

        hev_task_mutex_lock (self->mutex);
        if (self->tcp) {
            err = tcp_write (self->tcp, data, size, TCP_WRITE_FLAG_COPY);
            if (err == ERR_OK)
                err = tcp_output (self->tcp);
        }
        hev_task_mutex_unlock (self->mutex);
        if (!self->tcp || (err != ERR_OK))
            return -1;

        data += size;
        len -= size;
    }

    return 0;
}

static int
http_recv_fd (HevHttpSession *self, HevHttpBuffer *buffer)
{
    size_t len;
    ssize_t res;

    len = buffer->size - (buffer->last - buffer->data);
    if (!len)
        return -1;

    res = hev_task_io_socket_recv (self->remote_fd, buffer->last, len, 0,
                                   task_io_yielder, self);
    if (res <= 0)
        return -1;

    buffer->last += res;
    return 0;
}

static int
http_switch_splice (HevHttpSession *self, HevHttpBuffer *buffer, int upstream)
{
    size_t len;
    ssize_t res;

    LOG_D ("Session %s: switch splice", self->saddr);

    len = buffer->last - buffer->data;

    if (upstream)
        res = hev_task_io_socket_send (self->remote_fd, buffer->data, len,
                                       MSG_WAITALL, task_io_yielder, self);
    else
        res = http_send_pb (self, buffer->data, len);

    if (res < 0)
        return STEP_CLOSE_SESSION;

    return STEP_SPLICE_STREAM;
}

static int
http_switch_connect (HevHttpSession *self, HevHttpBuffer *buffer)
{
    struct pbuf *buf;
    size_t len;

    LOG_D ("Session %s: switch connect", self->saddr);

    len = buffer->last - buffer->data;
    hev_task_mutex_lock (self->mutex);
    buf = pbuf_alloc (PBUF_RAW, len, PBUF_RAM);
    hev_task_mutex_unlock (self->mutex);
    if (!buf)
        return STEP_CLOSE_SESSION;

    memcpy (buf->payload, buffer->data, len);
    if (!self->queue) {
        self->queue = buf;
    } else {
        pbuf_cat (buf, self->queue);
        self->queue = buf;
    }

    return STEP_CONNECT_ORIG;
}

static int
http_process_request_header (HevHttpSession *self, HevHttpParser *parser,
                             HevHttpBuffer *buffer)
{
    /* reset buffer */
    hev_http_buffer_reset (buffer);

    /* request line */
    for (;;) {
        int res = hev_http_parser_parse_request_line (parser, buffer);
        if (res == HEV_HTTP_PARSER_ERROR) {
            if (parser->code == 0)
                return http_switch_connect (self, buffer);
            else
                return http_switch_splice (self, buffer, 1);
        } else if (res == HEV_HTTP_PARSER_OK) {
            break;
        }

        if (http_recv_pb (self, buffer) < 0)
            return STEP_CLOSE_SESSION;
    }

    /* header lines */
    for (;;) {
        int res = hev_http_parser_parse_header_line (parser, buffer);
        if (res == HEV_HTTP_PARSER_ERROR)
            return STEP_CLOSE_SESSION;
        else if (res == HEV_HTTP_PARSER_OK)
            continue;
        else if (res == HEV_HTTP_PARSER_DONE)
            break;

        if (http_recv_pb (self, buffer) < 0)
            return STEP_CLOSE_SESSION;
    }

    /* connect for upgrade */
    {
        int i;

        for (i = 0; i < parser->header_used; i++) {
            HevHttpHeader *h = &parser->headers[i];

            if (strcmp (h->lowcase_name, "upgrade") == 0)
                return http_switch_connect (self, buffer);
        }
    }

    /* convert and forward */
    {
        struct iovec iov[7];
        struct msghdr mh = { .msg_iov = iov };
        unsigned int host_len = self->host_len;
        const char *host = self->host;
        ssize_t res;
        int i;

        for (i = 0; i < parser->header_used; i++) {
            HevHttpHeader *h = &parser->headers[i];

            if (strcmp (h->lowcase_name, "host") == 0) {
                host = h->value;
                host_len = h->value_len;
                break;
            }
        }

        iov[0].iov_base = (void *)parser->method;
        iov[0].iov_len = parser->method_len;
        iov[1].iov_base = " http://";
        iov[1].iov_len = strlen (iov[1].iov_base);
        iov[2].iov_base = (void *)host;
        iov[2].iov_len = host_len;
        iov[3].iov_base = (void *)parser->uri;
        iov[3].iov_len = parser->uri_len;
        iov[4].iov_base = " HTTP/1.1\r\nHost: ";
        iov[4].iov_len = strlen (iov[4].iov_base);
        iov[5].iov_base = (void *)host;
        iov[5].iov_len = host_len;
        iov[6].iov_base = "\r\n";
        iov[6].iov_len = strlen (iov[6].iov_base);
        mh.msg_iovlen = 7;

        res = hev_task_io_socket_sendmsg (self->remote_fd, &mh, MSG_WAITALL,
                                          task_io_yielder, self);
        if (res < 0)
            return STEP_CLOSE_SESSION;

        for (i = 0; i < parser->header_used; i++) {
            HevHttpHeader *h = &parser->headers[i];

            if (strcmp (h->lowcase_name, "host") == 0)
                continue;

            iov[0].iov_base = (void *)h->name;
            iov[0].iov_len = h->name_len;
            iov[1].iov_base = ": ";
            iov[1].iov_len = strlen (iov[1].iov_base);
            iov[2].iov_base = (void *)h->value;
            iov[2].iov_len = h->value_len;
            iov[3].iov_base = "\r\n";
            iov[3].iov_len = strlen (iov[3].iov_base);
            mh.msg_iovlen = 4;

            res = hev_task_io_socket_sendmsg (self->remote_fd, &mh, MSG_WAITALL,
                                              task_io_yielder, self);
            if (res < 0)
                return STEP_CLOSE_SESSION;
        }

        res = hev_task_io_socket_send (self->remote_fd, "\r\n", strlen ("\r\n"),
                                       MSG_WAITALL, task_io_yielder, self);
        if (res < 0)
            return STEP_CLOSE_SESSION;
    }

    return 0;
}

static int
http_process_response_header (HevHttpSession *self, HevHttpParser *parser,
                              HevHttpBuffer *buffer, int forward)
{
    /* reset buffer */
    hev_http_buffer_reset (buffer);

    /* status line */
    for (;;) {
        int res = hev_http_parser_parse_status_line (parser, buffer);
        if (res == HEV_HTTP_PARSER_ERROR)
            return http_switch_splice (self, buffer, 0);
        else if (res == HEV_HTTP_PARSER_OK)
            break;

        if (http_recv_fd (self, buffer) < 0)
            return STEP_CLOSE_SESSION;
    }

    /* header lines */
    for (;;) {
        int res = hev_http_parser_parse_header_line (parser, buffer);
        if (res == HEV_HTTP_PARSER_ERROR)
            return STEP_CLOSE_SESSION;
        else if (res == HEV_HTTP_PARSER_OK)
            continue;
        else if (res == HEV_HTTP_PARSER_DONE)
            break;

        if (http_recv_fd (self, buffer) < 0)
            return STEP_CLOSE_SESSION;
    }

    if (forward) {
        int res = http_send_pb (self, buffer->data, buffer->pos - buffer->data);
        if (res < 0)
            return STEP_CLOSE_SESSION;
    }

    return 0;
}

static int
http_process_body_content_up (HevHttpSession *self, HevHttpBuffer *buffer,
                              uint64_t length)
{
    size_t len = buffer->last - buffer->pos;
    if (len) {
        ssize_t res;

        if (len > length)
            len = length;

        res = hev_task_io_socket_send (self->remote_fd, buffer->pos, len,
                                       MSG_WAITALL, task_io_yielder, self);
        if (res < 0)
            return STEP_CLOSE_SESSION;
        buffer->pos += len;
        length -= len;
    }

    while (length) {
        ssize_t res;

        while (!self->queue) {
            if (task_io_yielder (HEV_TASK_WAITIO, self) < 0)
                return STEP_CLOSE_SESSION;
        }

        len = buffer->size;
        if (len > length)
            len = length;

        hev_task_mutex_lock (self->mutex);
        len = pbuf_copy_partial (self->queue, buffer->data, len, 0);
        self->queue = pbuf_free_header (self->queue, len);
        hev_task_mutex_unlock (self->mutex);
        length -= len;

        res = hev_task_io_socket_send (self->remote_fd, buffer->data, len,
                                       MSG_WAITALL, task_io_yielder, self);
        if (res < 0)
            return STEP_CLOSE_SESSION;
    }

    return 0;
}

static int
http_process_body_content_down (HevHttpSession *self, HevHttpBuffer *buffer,
                                uint64_t length)
{
    size_t len = buffer->last - buffer->pos;
    if (len) {
        int res;

        if (len > length)
            len = length;

        res = http_send_pb (self, buffer->pos, len);
        if (res < 0)
            return STEP_CLOSE_SESSION;
        buffer->pos += len;
        length -= len;
    }

    while (length) {
        ssize_t res;

        len = buffer->size;
        if (len > length)
            len = length;

        res = hev_task_io_socket_recv (self->remote_fd, buffer->data, len, 0,
                                       task_io_yielder, self);
        if (res <= 0)
            return STEP_CLOSE_SESSION;
        length -= res;

        res = http_send_pb (self, buffer->data, res);
        if (res < 0)
            return STEP_CLOSE_SESSION;
    }

    return 0;
}

static int
http_process_body_chunked_up (HevHttpSession *self, HevHttpParser *parser,
                              HevHttpBuffer *buffer)
{
    hev_http_buffer_reset (buffer);

    for (;;) {
        int res;

        res = hev_http_parser_parse_chunked (parser, buffer);
        if (res == HEV_HTTP_PARSER_ERROR) {
            return STEP_CLOSE_SESSION;
        } else if (res == HEV_HTTP_PARSER_OK) {
            uint64_t len = parser->chunk_size;
            len += buffer->pos - buffer->data;
            buffer->pos = buffer->data;
            if (http_process_body_content_up (self, buffer, len))
                return STEP_CLOSE_SESSION;
            parser->chunk_size = 0;
            hev_http_buffer_reset (buffer);
            continue;
        } else if (res == HEV_HTTP_PARSER_DONE) {
            uint64_t len = buffer->pos - buffer->data;
            buffer->pos = buffer->data;
            if (http_process_body_content_up (self, buffer, len))
                return STEP_CLOSE_SESSION;
            break;
        }

        if (http_recv_fd (self, buffer) < 0)
            return STEP_CLOSE_SESSION;
    }

    return 0;
}

static int
http_process_body_chunked_down (HevHttpSession *self, HevHttpParser *parser,
                                HevHttpBuffer *buffer)
{
    hev_http_buffer_reset (buffer);

    for (;;) {
        int res;

        res = hev_http_parser_parse_chunked (parser, buffer);
        if (res == HEV_HTTP_PARSER_ERROR) {
            return STEP_CLOSE_SESSION;
        } else if (res == HEV_HTTP_PARSER_OK) {
            uint64_t len = parser->chunk_size;
            len += buffer->pos - buffer->data;
            buffer->pos = buffer->data;
            if (http_process_body_content_down (self, buffer, len))
                return STEP_CLOSE_SESSION;
            parser->chunk_size = 0;
            hev_http_buffer_reset (buffer);
            continue;
        } else if (res == HEV_HTTP_PARSER_DONE) {
            uint64_t len = buffer->pos - buffer->data;
            buffer->pos = buffer->data;
            if (http_process_body_content_down (self, buffer, len))
                return STEP_CLOSE_SESSION;
            break;
        }

        if (http_recv_fd (self, buffer) < 0)
            return STEP_CLOSE_SESSION;
    }

    return 0;
}

static int
http_process_body (HevHttpSession *self, HevHttpParser *parser,
                   HevHttpBuffer *buffer, int upstream)
{
    uint64_t content_length = 0;
    int i, chunked = 0;

    for (i = 0; i < parser->header_used; i++) {
        HevHttpHeader *h = &parser->headers[i];

        if (strcmp (h->lowcase_name, "content-length") == 0) {
            int j;

            for (j = 0; j < h->value_len; j++)
                content_length = content_length * 10 + (h->value[j] - '0');
            break;
        }

        if (strcmp (h->lowcase_name, "transfer-encoding") == 0) {
            if (strncmp (h->value, "chunked", h->value_len) == 0) {
                chunked = 1;
                break;
            }
        }
    }

    if (content_length) {
        if (upstream)
            return http_process_body_content_up (self, buffer, content_length);
        return http_process_body_content_down (self, buffer, content_length);
    } else if (chunked) {
        if (upstream)
            return http_process_body_chunked_up (self, parser, buffer);
        return http_process_body_chunked_down (self, parser, buffer);
    }

    return 0;
}

static int
http_forward_http (HevHttpSession *self)
{
    HevHttpBuffer *buf[2];
    HevHttpParser *parser;
    int step = STEP_CLOSE_SESSION;

    buf[0] = hev_http_buffer_new (BUFFER_SIZE);
    if (!buf[0])
        goto exit;

    buf[1] = hev_http_buffer_new (BUFFER_SIZE);
    if (!buf[1])
        goto free_buf0;

    parser = hev_http_parser_new (64);
    if (!parser)
        goto free_buf1;

    for (;;) {
        int res;

        /* request */
        res = http_process_request_header (self, parser, buf[0]);
        if (res) {
            step = res;
            break;
        }
        res = http_process_body (self, parser, buf[0], 1);
        if (res) {
            step = res;
            break;
        }

        /* response */
        res = http_process_response_header (self, parser, buf[1], 1);
        if (res) {
            step = res;
            break;
        }
        res = http_process_body (self, parser, buf[1], 0);
        if (res) {
            step = res;
            break;
        }
    }

    hev_http_parser_destroy (parser);
free_buf1:
    hev_http_buffer_destroy (buf[1]);
free_buf0:
    hev_http_buffer_destroy (buf[0]);
exit:
    return step;
}

static int
http_forward_dns (HevHttpSession *self)
{
    struct iovec iov[2];
    struct msghdr mh = { .msg_iov = iov, .msg_iovlen = 2 };
    struct pbuf *buf;
    uint16_t dns_len;
    ssize_t len;

    /* dns request len */
    dns_len = htons (self->query->tot_len);
    iov[0].iov_base = &dns_len;
    iov[0].iov_len = 2;
    /* dns request */
    iov[1].iov_base = self->query->payload;
    iov[1].iov_len = self->query->tot_len;

    /* send dns request */
    len = hev_task_io_socket_sendmsg (self->remote_fd, &mh, MSG_WAITALL,
                                      task_io_yielder, self);
    if (len < 0) {
        LOG_W ("Session %s: send DNS request failed!", self->saddr);
        return STEP_CLOSE_SESSION;
    }

    /* recv dns response len */
    len = hev_task_io_socket_recv (self->remote_fd, &dns_len, 2, MSG_WAITALL,
                                   task_io_yielder, self);
    if (len <= 0) {
        LOG_W ("Session %s: receive DNS response failed!", self->saddr);
        return STEP_CLOSE_SESSION;
    }
    dns_len = ntohs (dns_len);

    /* check dns response len */
    if (dns_len >= 2048) {
        LOG_W ("Session %s: DNS response is invalid!", self->saddr);
        return STEP_CLOSE_SESSION;
    }

    hev_task_mutex_lock (self->mutex);
    buf = pbuf_alloc (PBUF_RAW, dns_len, PBUF_RAM);
    hev_task_mutex_unlock (self->mutex);
    if (!buf) {
        LOG_W ("Session %s: alloc dns buffer failed!", self->saddr);
        return STEP_CLOSE_SESSION;
    }

    /* recv dns response */
    len = hev_task_io_socket_recv (self->remote_fd, buf->payload, dns_len,
                                   MSG_WAITALL, task_io_yielder, self);
    if (len <= 0) {
        LOG_W ("Session %s: receive DNS response failed!", self->saddr);
        hev_task_mutex_lock (self->mutex);
        pbuf_free (buf);
        hev_task_mutex_unlock (self->mutex);
        return STEP_CLOSE_SESSION;
    }

    /* send dns response */
    hev_task_mutex_lock (self->mutex);
    udp_sendto (self->udp, buf, &self->addr, self->port);
    hev_task_mutex_unlock (self->mutex);

    return STEP_CLOSE_SESSION;
}

static int
http_send_connect_request (HevHttpSession *self)
{
    struct iovec iov[5];
    struct msghdr mh = { .msg_iov = iov, .msg_iovlen = 5 };
    unsigned int size;
    void *host;

    if (self->query) {
        host = (void *)hev_config_get_dns_address (&size);
    } else {
        host = (void *)self->host;
        size = self->host_len;
    }

    /*
     * CONNECT {host} HTTP/1.1\r\n
     * Host: {host}\r\n
     * \r\n
     */
    iov[0].iov_base = "CONNECT ";
    iov[0].iov_len = strlen (iov[0].iov_base);
    iov[1].iov_base = host;
    iov[1].iov_len = size;
    iov[2].iov_base = " HTTP/1.1\r\nHost: ";
    iov[2].iov_len = strlen (iov[2].iov_base);
    iov[3].iov_base = host;
    iov[3].iov_len = size;
    iov[4].iov_base = "\r\n\r\n";
    iov[4].iov_len = strlen (iov[4].iov_base);

    return hev_task_io_socket_sendmsg (self->remote_fd, &mh, MSG_WAITALL,
                                       task_io_yielder, self);
}

static int
http_recv_connect_response (HevHttpSession *self)
{
    HevHttpBuffer *buffer;
    HevHttpParser *parser;
    int res = 0;

    buffer = hev_http_buffer_new (128);
    if (!buffer)
        goto exit;

    parser = hev_http_parser_new (1);
    if (!parser)
        goto free_buffer;

    if (http_process_response_header (self, parser, buffer, 0))
        goto free_parser;

    res = parser->code;

free_parser:
    hev_http_parser_destroy (parser);
free_buffer:
    hev_http_buffer_destroy (buffer);
exit:
    return res;
}

static int
http_connect_orig (HevHttpSession *self)
{
    int res;

    res = http_send_connect_request (self);
    if (res < 0) {
        LOG_W ("Session %s: send HTTP CONNECT request failed!", self->saddr);
        return STEP_CLOSE_SESSION;
    }

    res = http_recv_connect_response (self);
    if (res != 200) {
        LOG_W ("Session %s: recv HTTP CONNECT response failed!", self->saddr);
        return STEP_CLOSE_SESSION;
    }

    return self->query ? STEP_FORWARD_DNS : STEP_SPLICE_STREAM;
}

static int
tcp_splice_f (HevHttpSession *self)
{
    ssize_t s;

    if (!self->queue)
        return 0;

    if (self->queue->next) {
        struct pbuf *p = self->queue;
        struct iovec iov[64];
        int i;

        for (i = 0; (i < 64) && p; p = p->next) {
            iov[i].iov_base = p->payload;
            iov[i].iov_len = p->len;
            i++;
        }

        s = writev (self->remote_fd, iov, i);
    } else {
        s = write (self->remote_fd, self->queue->payload, self->queue->len);
    }

    if (0 >= s) {
        if ((0 > s) && (EAGAIN == errno))
            return 0;
        else
            return -1;
    } else {
        hev_task_mutex_lock (self->mutex);
        self->queue = pbuf_free_header (self->queue, s);
        hev_task_mutex_unlock (self->mutex);
    }

    return 1;
}

static int
tcp_splice_b (HevHttpSession *self, uint8_t *buffer)
{
    err_t err = ERR_OK;
    size_t size;
    ssize_t s;

    if (!self->tcp)
        return -1;

    if (!(size = tcp_sndbuf (self->tcp)))
        return 0;

    if (size > BUFFER_SIZE)
        size = BUFFER_SIZE;

    s = read (self->remote_fd, buffer, size);
    if (0 >= s) {
        if ((0 > s) && (EAGAIN == errno))
            return 0;
        return -1;
    }

    hev_task_mutex_lock (self->mutex);
    if (self->tcp) {
        err = tcp_write (self->tcp, buffer, s, TCP_WRITE_FLAG_COPY);
        if (err == ERR_OK)
            err = tcp_output (self->tcp);
    }
    hev_task_mutex_unlock (self->mutex);
    if (!self->tcp || (err != ERR_OK))
        return -1;

    return 1;
}

static int
http_splice_stream (HevHttpSession *self)
{
    int err_f = 0;
    int err_b = 0;
    uint8_t *buffer;

    buffer = hev_malloc (BUFFER_SIZE);
    if (!buffer)
        return STEP_CLOSE_SESSION;

    for (;;) {
        HevTaskYieldType type = 0;

        if (!err_f) {
            int ret = tcp_splice_f (self);
            if (0 >= ret) {
                /* backward closed, quit */
                if (err_b)
                    break;
                if (0 > ret) { /* error */
                    /* forward error or closed, mark to skip */
                    err_f = 1;
                } else { /* no data */
                    type++;
                }
            }
        }

        if (!err_b) {
            int ret = tcp_splice_b (self, buffer);
            if (0 >= ret) {
                /* forward closed, quit */
                if (err_f)
                    break;
                if (0 > ret) { /* error */
                    /* backward error or closed, mark to skip */
                    err_b = 1;
                } else { /* no data */
                    type++;
                }
            }
        }

        if (task_io_yielder (type, self) < 0)
            break;
    }

    hev_free (buffer);
    return STEP_CLOSE_SESSION;
}

static int
http_close_session (HevHttpSession *self)
{
    if (self->remote_fd >= 0)
        close (self->remote_fd);

    hev_task_mutex_lock (self->mutex);
    if (self->query) {
        pbuf_free (self->query);
    } else {
        if (self->tcp) {
            tcp_recv (self->tcp, NULL);
            tcp_sent (self->tcp, NULL);
            tcp_err (self->tcp, NULL);
            if (tcp_close (self->tcp) != ERR_OK)
                tcp_abort (self->tcp);
        }
        if (self->queue)
            pbuf_free (self->queue);
    }
    hev_task_mutex_unlock (self->mutex);

    LOG_I ("Session %s: closed", self->saddr);

    if (self->saddr)
        hev_free (self->saddr);

    self->notify (self);
    hev_http_session_unref (self);

    return STEP_NULL;
}

static void
hev_http_session_task_entry (void *data)
{
    HevHttpSession *self = data;
    int step = STEP_CONNECT_PROXY;

    for (;;) {
        switch (step) {
        case STEP_CONNECT_PROXY:
            step = http_connect_proxy (self);
            break;
        case STEP_FORWARD_HTTP:
            step = http_forward_http (self);
            break;
        case STEP_FORWARD_DNS:
            step = http_forward_dns (self);
            break;
        case STEP_CONNECT_ORIG:
            step = http_connect_orig (self);
            break;
        case STEP_SPLICE_STREAM:
            step = http_splice_stream (self);
            break;
        case STEP_CLOSE_SESSION:
            step = http_close_session (self);
            break;
        default:
            return;
        }
    }
}
