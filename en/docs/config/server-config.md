---
hide:
  - toc
---

# Server Configuration

Currently, smartdns provides three server modes: UDP, TCP, and DOT.

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

## DOT Server

1. Configure with the `bind-tcp` parameter. For example:

    ```shell
    bind-tcp 0.0.0.0:53@eth0
    bind-tcp [::]:53@eth0
    bind-tcp :53@eth0
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

    If these three parameters are not specified, smartdns will automatically generate a self-signed cert `smartdns-cert.pem` and `smartdns-key.pem` key file in the `/etc/smartdns` directory, with CN as smartdns.

1. Optional, the `tcp-idle-time` parameter controls the TCP idle disconnect time.

    ```shell
    tcp-idle-time 120
    ```
