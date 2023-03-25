---
hide:
  - toc
---

# Query through Proxy

Smartdns supports querying through proxy servers, including socks5 and http proxy servers. Socks5 supports both udp and tcp types of proxies, while http does not support udp proxies. Please note the difference.

## Configuration Steps

1. Use `proxy-server` to configure the proxy server.

    ```shell
    proxy-server socks5://1.2.3.4 -name socks5
    ```

1. Use the `-proxy` parameter to configure the server to use the proxy server:

    ```shell
    server 8.8.8.8 -proxy socks5
    ```

Note that the `-name` for `proxy-server` and the `-proxy` for server must have the same name.
