---
hide:
  - toc
---

# 域名规则

为方便对同一个域名设置多个规则，smartdns提供了`domain-rules`参数，可以对域名设置多个规则。

## 规则设置

使用`domain-rules`设置多个规则，如：

  ```
  domain-rules /a.com/ -g group -address #6 -ipset ipset
  # 设置全局规则。
  domain-rules /./ -no-cache
  ```

  domain-rules的选项请阅读配置选项。常用选项:

  |参数|功能|
  |---|---|
  |`-group`|设置对应的规则组|
  |`-address`|指定域名地址|
  |`-nameserver`|指定上游服务器组|
  |`-speed-check-mode`|测速模式|
  |`-dualstack-ip-selection`|双栈优选|
  |`-no-cache`|停止缓存|
  |`-no-ip-alias`|忽略ip集合规则|
  |`-ipset [ipsetname]`|将对应请求的结果放入指定ipset|
  |`-nftset [nftsetname]`|将对应的请求结果放入指定的nftset|


## 域名通配

 /domain/域名匹配规则符号。

  ```shell
  // 通配
  *-a.example.com 
  // 仅匹配子域名
  *.example.com
  // 仅匹配主域名
  -.example.com
  ```

  注意：* 和 - 仅支持写在域名开头。其他位置的写法均不支持。

## 域名集合

在有/domain/配置的选项使用域名集合，只需要将`/domain/`配置为`/domain-set:[集合名称]/`即可，如：

  ```shell
  domain-set -name ad -file /etc/smartdns/ad-list.conf
  domain-rules /domain-set:ad/ -a #
  ```
