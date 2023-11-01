---
hide:
  - toc
---

# Docker

## Description

SmartDNS provides a Docker image for quick installation.

## Configuration

Create the configuration file /etc/smartdns/smartdns.conf and add the following configuration:

```
bind [::]:53
server 8.8.8.8
server 1.1.1.1
```

## Run image

```
docker run -d --name smartdns --restart=always -p 53:53/udp -v /etc/smartdns:/etc/smartdns pymumu/smartdns:latest
```
