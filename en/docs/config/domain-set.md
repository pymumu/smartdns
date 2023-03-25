---
hide:
  - toc
---

# Usage of Domain Set

To facilitate configuring domain names by collection, the domain set can be specified for configuration with `/domain/`. The specific method is:

1. Use `domain-set` to configure the collection file, such as:

    ```shell
    domain-set -name ad -file /etc/smartdns/ad-list.conf
    ```

    The format of `ad-list.conf` is one domain per line, such as:

    ```shell
    ad.com
    site.com
    ```

2. Use the domain set in the options with `/domain/` configuration. Just set `/domain/` to `/domain-set:[collection name]/`, such as:

    ```shell
    address /domain-set:ad/#
    domain-rules /domain-set:ad/ -a #
    nameserver /domain-set:ad/server
    ```
