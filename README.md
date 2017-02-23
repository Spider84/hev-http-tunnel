# HevHttpTunnel

[![status](https://gitlab.com/hev/hev-http-tunnel/badges/master/pipeline.svg)](https://gitlab.com/hev/hev-http-tunnel/commits/master)

A tunnel over HTTP proxy.

**Features**
* Redirect TCP connections.
* Redirect DNS queries. (over http proxy)
* IPv4/IPv6. (dual stack)

## How to Build

**Linux**:
```bash
git clone --recursive git://github.com/heiher/hev-http-tunnel
cd hev-http-tunnel
make
```

**Android**:
```bash
mkdir hev-http-tunnel
cd hev-http-tunnel
git clone --recursive git://github.com/heiher/hev-http-tunnel jni
ndk-build
```

## How to Use

### Config

```yaml
tunnel:
  # Interface name
  name: tun0
  # Interface MTU
  mtu: 8192
  # IPv4 address
  ipv4:
    address: 10.0.0.2
    gateway: 10.0.0.1
    prefix: 30
  # IPv6 address
  ipv6:
    address: 'fc00::2'
    gateway: 'fc00::1'
    prefix: 126
  # Domain name service
  dns:
    port: 53

# Upstream DNS
dns:
  # DNS port (TCP)
  port: 5353
  # DNS address (ipv4/ipv6)
  address: 208.67.222.222

# Http Proxy
servers:
  srv:
    # Http server port
    port: 80
    # Http server address (ipv4/ipv6)
    address: 127.0.0.1

#misc:
   # null, stdout, stderr or file-path
#  log-file: null
   # debug, info, warn or error
#  log-level: warn
   # If present, run as a daemon with this pid file
#  pid-file: /run/hev-http-tunnel.pid
   # If present, set rlimit nofile; else use default value
#  limit-nofile: 1024
```

### Run

```bash
bin/hev-http-tunnel conf/main.yml

# Bypass upstream http server
sudo ip route add HTTP_SERVER dev DEFAULT_IFACE metric 10

# Route others
sudo ip route add default dev tun0 metric 20
```

## Authors
* **Heiher** - https://hev.cc

## License
LGPL
