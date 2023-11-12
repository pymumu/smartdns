---
hide:
  - toc
---

# 服务端配置

smartdns目前提供了UDP, TCP, DOT, DOH四种服务端模式。

## UDP服务端

1. 通过`bind`参数配置，配置例子如下：

    ```shell
    bind 0.0.0.0:53@eth0
    bind [::]:53@eth0
    bind :53@eth0
    ```

    选项中:

    * @eth0，表示仅在对应的网口上提供服务。
    * [::]:53， 表示监听IPV6和IPV4地址。
    * :53，表示监听IPV4地址

## TCP服务端

1. 通过`bind-tcp`参数配置，配置例子如下：

    ```shell
    bind-tcp 0.0.0.0:53@eth0
    bind-tcp [::]:53@eth0
    bind-tcp :53@eth0
    ```

1. 可选，参数tcp-idle-time控制TCP空闲断链时间

    ```shell
    tcp-idle-time 120
    ```

## DOT,DOH服务端

1. 通过`bind-tls`, `bind-https`参数配置，配置例子如下：

    ```shell
    # DOT 服务器
    bind-tls 0.0.0.0:853@eth0
    bind-tls [::]:853@eth0
    bind-tls :853@eth0

    # DOH 服务器
    bind-https 0.0.0.0:443@eth0
    bind-https [::]:443@eth0
    bind-https :443@eth0

    ```

1. 设置证书和密钥文件

    ```shell
    bind-cert-file smartdns-cert.pem
    bind-cert-key-file smartdns-key.pem
    bind-cert-key-pass pass
    ```

    选项中:

    * bind-cert-file: 表示证书文件路径。
    * bind-cert-key-file：表示证书密钥文件路径。
    * bind-cert-key-pass： 表示证书密钥文件密码，可选。

    注意：

    上述三个参数如果不指定的情况下，smartdns将会自动在/etc/smartdns目录自动生成自签名证书`smartdns-cert.pem`和`smartdns-key.pem` key文件，CN为smartdns。

1. 可选，参数tcp-idle-time控制TCP空闲断链时间

    ```shell
    tcp-idle-time 120
    ```

## 第二DNS服务

bind-*参数除了支持基本的启用服务外，还支持更多的附加特性，可以作为特殊因为的第二DNS服务器使用。对应的可以启用的功能为：

1. 配置样例：

    ```shell
    bind :53 -no-rule-addr -no-speed-check -no-cache
    ```

1. 参数介绍：

    |参数|功能|
    |---|---|
    |-no-rule-addr|跳过 address 规则|
    |-no-rule-nameserver|跳过 Nameserver 规则|
    |-no-rule-ipset|跳过 ipset 和 nftset 规则|
    |-no-rule-soa|跳过 SOA(#) 规则|
    |-no-dualstack-selection|停用双栈测速|
    |-no-speed-check|停用测速|
    |-no-cache|停止缓存|
    |-force-aaaa-soa|禁用IPV6查询|
