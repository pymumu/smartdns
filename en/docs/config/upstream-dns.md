---
hide:
    - toc
---

# Upstream DNS Servers

SmartDNS provides multiple query methods, currently supporting UDP, TCP, DOT, DOH, DOQ, and DOH3. These query protocols have their own advantages and disadvantages in terms of performance and security.   
You can configure them as needed. The table below provides a description of these protocols:

Configuration Parameter | Protocol | Performance | Security | Number of Public Servers | Description
--|--|--|--|--|--
server | UDP | Excellent | Poor | Many | Queries via UDP protocol. Results can be obtained with 0-RTT, but security is not guaranteed.
server-tcp | TCP | Good | Poor | Many | Queries via TCP protocol. Requires a three-way handshake, and security is not guaranteed. Mainly used as a fallback when UDP queries fail.
server-tls | DOT | Average | Good | Moderate | Queries via TLS. Requires a TCP three-way handshake and TLS protocol handshake. Performance is poor, but security is guaranteed.
server-https | DOH | Average | Good | Moderate | Queries via HTTPS. Built on TLS and uses the HTTP protocol. Benefits include compatibility with existing HTTP protocols.
server-quic | DOQ | Excellent | Good | Very Few | Queries via QUIC. Performance and security are both guaranteed, but there are currently very few public servers.
server-h3 | DOH3 | Good | Good | Very Few | Adds HTTP protocol on top of QUIC. Offers good performance and compatibility, but there are currently very few public servers.

## Configuring UDP Servers

1. Configure using the `server` parameter. Examples:

    ```shell
    # Standard configuration
    server 1.1.1.1
    # URI-based configuration
    server udp://1.1.1.1
    # Use -g to set server groups. A server can belong to multiple groups.
    server 1.1.1.1 -g group1 -g group2
    # Use -e|-exclude-default-group to exclude the server from the default group.
    server 1.1.1.1 -e -g office
    ```

1. Common parameter descriptions:

    * `-g|-group`: Assigns the server to a domain group. Used with `nameserver /domain/group` to query specific domains using designated servers. A server can belong to multiple domain groups. The `-g` parameter can be repeated.
    * `-e|-exclude-default-group`: Excludes the server from the default group. By default, all upstream servers are added to the default group. Domains without a specified group will use the default group for queries. To prevent domain leakage, this parameter can be set.
    * `-proxy`: Configures the server to use a proxy for queries. Used with `proxy-server`.
    * `-b|-bootstrap-dns`: Sets the DNS as a bootstrap DNS, used only when resolving domain-based servers. If `bootstrap-dns` is not configured, the system will automatically use IP-based servers to resolve domains.
    * `-interface`: Specifies the port for queries.

    For more parameters, refer to the configuration parameter documentation.

## Configuring TCP Servers

1. Configure TCP servers using `server-tcp`. The basic parameters are the same as for UDP servers. Examples:

    ```shell
    # Standard configuration
    server-tcp 1.1.1.1
    # URI-based configuration
    server tcp://1.1.1.1
    # Set TCP connection timeout.
    server-tcp 1.1.1.1 -tcp-keepalive 30
    ```

1. Common parameter descriptions:

    * `-tcp-keepalive`: Sets the TCP connection idle timeout in seconds, depending on the server.
    * Other basic parameters are the same as for the UDP protocol.

## Configuring TLS Servers (DOT)

1. Configure TLS servers using `server-tls`. The basic parameters are the same as for TCP servers. Examples:

    ```shell
    # Standard configuration
    server-tls 1.1.1.1
    # Predefine the server IP to avoid domain resolution.
    server-tls dns.google -host-ip 8.8.4.4
    # Verify the SAN field of the remote server's certificate.
    server-tls dns.google -tls-host-verify dns.google
    # Set the host name for SNI in TLS.
    server-tls 8.8.8.8 -host-name dns.google
    # Validate SPKI pin.
    server-tls 8.8.8.8 -spki-pin 3N9hMehDPwrM/PgifVYFZV4c3+H+GAKmhBDAtdoPgtA=
    # Skip certificate validation.
    server-tls 8.8.8.8 -k
    ```

1. Common parameter descriptions:

    * `-host-ip`: Forces the IP address for the server's domain to avoid additional resolution.
    * `-tls-host-verify`: Verifies the SAN or CN domain in the certificate.
    * `-host-name`: Forces the SNI name in the TLS certificate. Use `-` to omit the SNI name.
    * `-spki-pin`: An alternative method for server validation without requiring a certificate chain.
    * `-k|-no-check-certificate`: Skips certificate validation. Not recommended unless necessary, as it compromises security.
    * Other basic parameters are the same as for the TCP protocol.

## Configuring HTTPS Servers (DOH)

1. Configure HTTPS servers using `server-https`. The basic parameters are the same as for TLS servers. Examples:

    ```shell
    # Standard configuration
    server-https https://dns.google/dns-query
    # Specify HTTP host information.
    server-https 8.8.8.8 -host-name dns.google -http-host dns.google
    ```

1. Common parameter descriptions:

    * `-http-host`: Forces the HOST field in the HTTP protocol. By default, this value copies the upstream server parameter.
    * Other basic parameters are the same as for the TLS protocol.

## Configuring QUIC Servers (DOQ)

1. Configure DoQ servers using `server-quic`. The basic parameters are the same as for TLS servers. Examples:

    ```shell
    # Standard configuration
    server-quic 223.5.5.5
    ```

1. Common parameter descriptions:

    * Basic parameters are the same as for the TLS protocol.

## Configuring HTTP3 Servers (DOH3)

1. Configure DoH3 servers using `server-h3`. The basic parameters are the same as for HTTPS servers. Examples:

    ```shell
    # Standard configuration
    server-h3 h3://dns.alidns.com/dns-query
    # Alternative compatible syntax
    server-http3 http3://dns-unfiltered.adguard.com/dns-query
    ```

1. Common parameter descriptions:

    * Basic parameters are the same as for the HTTPS protocol.
