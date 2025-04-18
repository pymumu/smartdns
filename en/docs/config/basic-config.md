---
hide:
  - toc
---

# Basic Configuration

The smartdns configuration options are quite powerful, but as a basic DNS service, only the service port and upstream servers need to be configured. Other parameters can be left as default, which is the best configuration for local home networks.

## Sample Configuration

1. To provide service and accelerate DNS queries, the following configuration can be included in the smartdns.conf file:

    ```shell
    # Listen on port 53
    bind [::]:53
    # Configure upstream servers
    server 8.8.8.8
    server 114.114.114.114
    server 202.96.128.166:53
    server-tls 1.1.1.1
    server-quic 1.1.1.1
    ```

    In the options:

    * `bind` indicates that the service end is opened and the corresponding port is listened to. `:53` binds IPv4 port 53 and `[::]:53` binds IPv6 port 53. The latter also binds IPv4 ports in most systems.
    * `server` indicates the upstream server IP address, and the port can be omitted. If secure access to upstream is required, `server-tls`, `server-https`, `server-quic` can be used. URI can also be used, such as `server tls://1.1.1.1:853`.
    * If `server` is not specified, the system DNS address in the `/etc/resolv.conf` file will be automatically read.
