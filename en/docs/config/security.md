---
hide:
  - toc
---

# Security Related

smartdns is a DNS server that is bound to port 53 by default. Running smartdns in root permissions may lead to external data queries. Therefore, we can improve the security of smartdns as follows:

## Run as non-root user

Specify a non-root user to run, such as running as nobody

```shell
user nobody
```

## Bind to a specific IP or NIC

Specify the IP address or NIC to bind to via the `bind` parameter

1. Bind to a specific IP

  ```shell
  bind 192.168.1.1:53
  ```

1. Bind to a specific NIC

  ```shell
  bind [::]:53@eth0
  ```

## Use a TLS server to provide queries to the public network

Provide services to outside world through a TLS server

```shell
bind-tls [::]:853@eth0
```

## Enable Audit Logging

SmartDNS can enable audit logging to record DNS query requests with the following configuration:

```
audit-enable yes
audit-num 16
audit-size 16M
audit-file /var/log/smartdns/smartdns-audit.log
```
