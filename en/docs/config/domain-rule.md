---
hide:
  - toc
---

# Domain Rules

To facilitate setting multiple rules for the same domain, smartdns provides the `domain-rules` parameter, which allows you to set multiple rules for a domain.

1. Use the `domain-rules` parameter to set multiple rules, for example:

    ```
    domain-rules /a.com/ -g group -address #6 -ipset ipset
    ```

    Please refer to the configuration options for more information on the `domain-rules` options.

1. When using domain sets in options with `/domain/` configuration, you only need to replace `/domain/` with `/domain-set:[set name]/`, for example:

    ```shell
    domain-set -name ad -file /etc/smartdns/ad-list.conf
    domain-rules /domain-set:ad/ -a #
    ```

    ```shell
    domain-set -name ad -file /etc/smartdns/ad-list.conf
    domain-rules /domain-set:ad/ -a #
    ```
