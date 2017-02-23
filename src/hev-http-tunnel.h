/*
 ============================================================================
 Name        : hev-http-tunnel.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 Everyone.
 Description : Http Tunnel
 ============================================================================
 */

#ifndef __HEV_HTTP_TUNNEL_H__
#define __HEV_HTTP_TUNNEL_H__

int hev_http_tunnel_init (int tunfd);
void hev_http_tunnel_fini (void);

int hev_http_tunnel_run (void);
void hev_http_tunnel_stop (void);

#endif /* __HEV_HTTP_TUNNEL_H__ */
