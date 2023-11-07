---
hide:
  - toc
---

# Using IP Address Set

To facilitate the configuration of IP addresses according to sets, for configurations that use `ip/subnet`, IP address sets can be specified for easy maintenance. The specific method is as follows:

1. Use ip-set to configure the set file, such as

    ```shell
    ip-set -name cloudflare -file /etc/smartdns/cloudflare-list.conf
    ```

    The format of cloudflare-list.conf is one IP address per line, such as:

    ```shell
    1.2.3.4
    192.168.1.1/24
    ```

1. Use IP address sets for options with `ip/subnet` configurations, simply configure `ip/subnet` as `ip-set:[set name]`, such as:

    ```shell
    ignore-ip ip-set:cloudflare
    ip-rules ip-set:cloudflare -whitelist-ip
    ip-alias ip-set:cloudflare 192.168.1.1
    ```
