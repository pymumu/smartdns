---
hide:
  - toc
---

# 客户端规则

smartdns支持根据客户端IP，MAC地址，对客户端设置不同的规则，可以实现：

  * 家长控制：限制特定客户端可访问的网站。
  * 访问控制：禁止未经允许的客户端查询。
  * 基于客户端域名分流查询：设置规则组和上游组绑定，不同的客户端查询不同的上游。

## 家长控制

  设置smartdns针对特定的客户端使用特定的上游查询，也可以设置禁止访问特定的域名或IP地址，来实现家长控制。

  ```
  # 启用规则组
  group-begin child
  # 设置规则组对应的客户端IP
  client-rules 192.168.1.13
  # 设置规则对应的客户端MAC地址
  client-rules 01:02:03:04:05:06
  # 设置规则组使用的上游服务器
  server 1.2.3.4 -e
  # 禁止特定域名
  address /block.com/#
  # 禁止特定IP
  ignore-ip 2.2.2.2
  group-end
  ```

为方便管理，也可采用多配置文件的方式，如

  1. 主配置文件

    ```
    conf-file child.conf -group child
    ```

  1. 包含的配置文件

    ```
    # 设置规则组对应的客户端IP
    client-rules 192.168.1.13
    # 设置规则组使用的上游服务器
    server 1.2.3.4 -e
    # 禁止特定域名
    address /block.com/#
    # 禁止特定IP
    ignore-ip 2.2.2.2
    ```

    其中group-begin和group-end的配置块，等价于conf-file -group 包含的配置文件，

## 访问控制

smartdns支持基本的ACL功能，可以通过如下参数开启和设置允许访问的主机。

```
# 启用ACL
acl-enable yes
# 设置允许访问的主机
client-rules 192.168.1.2/24
```

## 基于客户端域名分流查询

类似家长控制，smartdns可以将特定需要分流和配合ipset/nftset访问的主机，进行分流。

  1. 主配置文件

    ```
    conf-file oversea.conf -group oversea
    ```

  1. 包含的配置文件

    ```
    # 设置规则组对应的客户端IP
    client-rules 192.168.1.13
    # 设置规则组使用的上游服务器
    server-https https://1.2.3.4 -e
    server-tls tls://1.2.3.4 -e
    server-quic quic://1.2.3.4 -e
    # 禁止测速
    speed-check-mode none
    # 禁止IPV6和HTTPS记录
    force-qtype-SOA 28 65
    # 设置ipset
    ipset oversea
    ```