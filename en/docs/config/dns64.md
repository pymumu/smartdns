---
hide:
  - toc
---

# DNS64

DNS64 is used to support accessing IPV4 websites in a pure IPV6 network, smartdns also provides support for this, and can use the dns64 parameter to configure the DNS64 server.

## Configuration Steps

1. Use `dns64 ip/mask` to configure alias name.

    ```shell
    dns64 64:ff9b::/96
    ```

1. In a pure IPV6 environment, it is recommended to disable the dual stack optimization function.

    ```shell
    dualstack-ip-selection no
    ```
