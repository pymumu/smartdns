---
hide:
  - toc
---

# 通过代理查询

smartdns支持通过代理服务器进行查询，支持的代理服务器有socks5和http代理服务器。socks5支持udp和tcp类型的代理，而http不支持udp代理，注意区分。

## 配置步骤

1. 使用`proxy-server`配置代理服务器

    ```shell
    proxy-server socks5://1.2.3.4 -name socks5
    ```

1. 使用`-proxy`参数，配置server使用代理服务器：

    ```shell
    server 8.8.8.8 -proxy socks5
    ```

注意proxy-server的`-name`和server的`-proxy`须为同一个名称。
