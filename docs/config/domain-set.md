---
hide:
  - toc
---

# 域名集合的使用

为方便按集合配置域名，对于有/domain/的配置，可以指定域名集合，方便维护。具体方法为：

1. 使用`domain-set`配置集合文件，如

    ```shell
    domain-set -name ad -file /etc/smartdns/ad-list.conf
    ```

    ad-list.conf的格式为一个域名一行，如

    ```shell
    ad.com
    site.com
    ```

1. 在有/domain/配置的选项使用域名集合，只需要将`/domain/`配置为`/domain-set:[集合名称]/`即可，如：

    ```shell
    address /domain-set:ad/#
    domain-rules /domain-set:ad/ -a #
    nameserver /domain-set:ad/server
    ```
