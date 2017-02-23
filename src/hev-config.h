/*
 ============================================================================
 Name        : hev-config.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 Everyone.
 Description : Config
 ============================================================================
 */

#ifndef __HEV_CONFIG_H__
#define __HEV_CONFIG_H__

typedef struct _HevConfigServer HevConfigServer;

struct _HevConfigServer
{
    char *name;
    struct sockaddr_in6 *addr;
    int addr_len;
    int weight;
};

int hev_config_init (const char *config_path);
void hev_config_fini (void);

const char *hev_config_get_tunnel_name (void);
unsigned int hev_config_get_tunnel_mtu (void);

const char *hev_config_get_tunnel_ipv4_address (void);
const char *hev_config_get_tunnel_ipv4_gateway (void);
unsigned int hev_config_get_tunnel_ipv4_prefix (void);

const char *hev_config_get_tunnel_ipv6_address (void);
const char *hev_config_get_tunnel_ipv6_gateway (void);
unsigned int hev_config_get_tunnel_ipv6_prefix (void);

unsigned int hev_config_get_tunnel_dns_port (void);

const char *hev_config_get_dns_address (unsigned int *len);

unsigned int hev_config_get_server_count (void);
HevConfigServer *hev_config_get_server (unsigned int id);

unsigned int hev_config_get_perfect_server (void);
void hev_config_set_perfect_server (unsigned int id);

const char *hev_config_get_misc_pid_file (void);

int hev_config_get_misc_limit_nofile (void);

const char *hev_config_get_misc_log_file (void);
const char *hev_config_get_misc_log_level (void);

#endif /* __HEV_CONFIG_H__ */
