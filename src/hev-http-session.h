/*
 ============================================================================
 Name        : hev-http-session.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 Everyone.
 Description : Http Session
 ============================================================================
 */

#ifndef __HEV_HTTP_SESSION_H__
#define __HEV_HTTP_SESSION_H__

#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <lwip/pbuf.h>
#include <lwip/ip_addr.h>

#include <hev-task.h>

typedef struct _HevHttpSessionBase HevHttpSessionBase;
typedef struct _HevHttpSession HevHttpSession;
typedef void (*HevHttpSessionCloseNotify) (HevHttpSession *self);

struct _HevHttpSessionBase
{
    HevHttpSessionBase *prev;
    HevHttpSessionBase *next;
    HevTask *task;
    int hp;
};

HevHttpSession *hev_http_session_new_tcp (struct tcp_pcb *pcb,
                                          HevTaskMutex *mutex,
                                          HevHttpSessionCloseNotify notify);
HevHttpSession *hev_http_session_new_dns (struct udp_pcb *pcb, struct pbuf *p,
                                          const ip_addr_t *addr, u16_t port,
                                          HevTaskMutex *mutex,
                                          HevHttpSessionCloseNotify notify);

HevHttpSession *hev_http_session_ref (HevHttpSession *self);
void hev_http_session_unref (HevHttpSession *self);

void hev_http_session_run (HevHttpSession *self);

#endif /* __HEV_HTTP_SESSION_H__ */
