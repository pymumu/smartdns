---
hide:
  - toc
---

# Bootstrap DNS

For upstream servers of domain names, SmartDNS will use IP address servers for resolution, so BootStrap DNS usually does not need to be configured. However, if special needs arise, BootStrap DNS needs to be specified, which can be configured in the following ways:

1. Method 1: Specify BootStrap DNS for all servers

    Use the `-bootstrap-dns` parameter to specify a specific server as the BootStrap DNS.

    ```shell
    server 1.2.3.4 -bootstrap-dns
    server dns.server
    ```

1. Method 2: For specific servers

    Use the `nameserver /domain/bootstrap-dns` parameter to specify that a specific domain name uses a specific DNS for resolution.

    ```shell
    # Configure bootstrap DNS
    server 1.2.3.4 -group bootstrap-dns
    nameserver /dns.server/bootstrap-dns
    # This server will use 1.2.3.4 for resolution
    server dns.server
    ```
