---
hide:
  - toc
---

# Server Configuration

Currently, smartdns provides four server modes: UDP, TCP, DOH, and DOT.

## UDP Server

1. Configure with the `bind` parameter. For example:

    ```shell
    bind 0.0.0.0:53@eth0
    bind [::]:53@eth0
    bind :53@eth0
    ```

    Options:

    * @eth0 indicates that it only provides services on the corresponding NIC.
    * [::]:53 indicates that it listens to both IPV6 and IPV4 addresses.
    * :53 represents listening to IPV4 addresses.

## TCP Server

1. Configure with the `bind-tcp` parameter. For example:

    ```shell
    bind-tcp 0.0.0.0:53@eth0
    bind-tcp [::]:53@eth0
    bind-tcp :53@eth0
    ```

1. Optional, the `tcp-idle-time` parameter controls the TCP idle disconnect time.

    ```shell
    tcp-idle-time 120
    ```

## DOT, DOH Server

1. Configure with the `bind-tls`, `bind-https` parameter. For example:

    ```shell
    # DOT server
    bind-tls 0.0.0.0:853@eth0
    bind-tls [::]:853@eth0
    bind-tls :853@eth0

    # DOH server
    bind-https 0.0.0.0:443@eth0
    bind-https [::]:443@eth0
    bind-https :443@eth0

    ```

1. Set certificate and key files

    ```shell
    bind-cert-file smartdns-cert.pem
    bind-cert-key-file smartdns-key.pem
    bind-cert-key-pass pass
    ```

    Options:

    * `bind-cert-file`: Specifies the certificate file path.
    * `bind-cert-key-file`: Specifies the certificate key file path.
    * `bind-cert-key-pass`: Specifies the password for the certificate key file. (Optional)

    Note:

    If the above three parameters are not specified, smartdns will automatically generate a certificate chain in the same directory as the `smartdns.conf` configuration file. Clients can manually add the root certificate to the trusted certificate authority to use DOT and DOH services. The files are as follows:
    
    File|Function|Validity|Description
    --|--|--|--
    smartdns-root-key.pem|Root certificate private key|10 years|Automatically generated root certificate private key, used to sign the server certificate and added to the trusted root certificate authority on the client machine.
    smartdns-key.pem|Server certificate private key|13 months|Automatically generated server certificate private key, used for DOH, DOT, and WebUI HTTPS encryption on the server.
    smartdns-cert.pem|Server certificate|13 months|Automatically generated server certificate, signed using smartdns-root-key.pem. The SAN is automatically set to the host IP, hostname, and the domain name set by `ddns-domain`.

    If the server certificate expires after 13 months, restarting the smartdns server will automatically regenerate the server certificate.

1. Optional, the `tcp-idle-time` parameter controls the TCP idle disconnect time.

    ```shell
    tcp-idle-time 120
    ```

## Second DNS Server

In addition to supporting basic service, the `bind-*` parameter also supports more additional features, which can be used as a special second DNS server for specific needs. The corresponding functions that can be enabled are:

1. Configuration example:

    ```shell
    bind :53 -no-rule-addr -no-speed-check -no-cache
    ```

1. Parameter introduction:

   | Parameter | Function                                  |
   | --------- | ---------------------------------------- |
   | `-group` | Set the corresponding upstream server group |
   | `-no-rule-addr` | Skip address rules                  |
   | `-no-rule-nameserver` | Skip Nameserver rules           |
   | `-no-rule-ipset` | Skip ipset and nftset rules         |
   | `-no-rule-soa` | Skip SOA(#) rules                      |
   | `-no-dualstack-selection` | Disable dual-stack speed test |
   | `-no-speed-check` | Disable speed test                       |
   | `-no-cache` | Stop caching                               |
   | `-force-aaaa-soa` | Disable IPV6 queries                |
   | `-no-ip-alias` |Ignore IP alias rules|
   | `-ipset [ipsetname]` |Put the corresponding request result into the specified ipset|
   | `-nftset [nftsetname]` |Put the corresponding request result into the specified nftset|
