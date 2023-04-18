---
hide:
  - toc
---

# DNS64

DNS64用于支持纯IPV6网络访问IPV4网站，smartdns对此也提供了支持，可使用dns64参数配置DNS64服务器。

## 配置步骤

1. 使用`dns64 ip/mask`配置DNS64前缀。

    ```shell
    dns64 64:ff9b::/96
    ```

1. 在纯IPV6的环境下，建议关闭双栈优选功能。

    ```shell
    dualstack-ip-selection no
    ```
