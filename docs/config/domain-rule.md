---
hide:
  - toc
---

# 域名规则

为方便对同一个域名设置多个规则，smartdns提供了`domain-rules`参数，可以对域名设置多个规则。

1. 使用`domain-rules`设置多个规则，如：

  ```
  domain-rules /a.com/ -g group -address #6 -ipset ipset
  ```

  domain-rules的选项请阅读配置选项。

1. 在有/domain/配置的选项使用域名集合，只需要将`/domain/`配置为`/domain-set:[集合名称]/`即可，如：

  ```shell
  domain-set -name ad -file /etc/smartdns/ad-list.conf
  domain-rules /domain-set:ad/ -a #
  ```
