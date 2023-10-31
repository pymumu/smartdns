---
hide:
  - toc
---

# IP地址集合的使用

为方便按集合配置IP地址，对于使用到`ip/subnet`的配置，可以指定IP地址集合，方便维护。具体方法为：

1. 使用`ip-set`配置集合文件，如

    ```shell
    ip-set -name cloudflare -file /etc/smartdns/cloudflare-list.conf
    ```

    cloudflare-list.conf的格式为一个IP地址一行，如

    ```shell
    1.2.3.4
    192.168.1.1/24
    ```

1. 在有`ip/subnet`配置的选项使用IP地址集合，只需要将`ip/subnet`配置为`ip-set:[集合名称]/`即可，如：

    ```shell
    ignore-ip ip-set:cloudflare
    ip-rules ip-set:cloudflare -whitelist-ip
    ip-alias ip-set:cloudflare 192.168.1.1
    ```
