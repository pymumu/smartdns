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

    上述三个参数如果不指定的情况下，smartdns将会自动在`smartdns.conf`配置文件同级目录自动生成证书链, 客户端可将根证书手工加入受信任的证书机构使用DOT，DOH服务，文件如下：
    
    文件|功能|有效期|说明
    --|--|--|--
    smartdns-root-key.pem|根证书私钥|10年|自动生成的根证书私钥，用于给服务端证书签名，并加入客户端机器的受信任的根证书机构
    smartdns-key.pem|服务端证书密钥|13个月|自动生成的服务端证书私钥，用于服务端DOH,DOT,WebUI HTTPS加密使用
    smartdns-cert.pem|服务端证书|13个月|自动生成的服务端证书，使用smartdns-root-key.pem签名，SAN自动设置为主机IP，主机名，和`ddns-domain`设置的域名

    如果服务端证书13个月过期后，重启smartdns服务器可自动重新生成服务端证书。


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
    |`-group`|设置对应的上游服务器组|
    |`-no-rule-addr`|跳过 address 规则|
    |`-no-rule-nameserver`|跳过 Nameserver 规则|
    |`-no-rule-ipset`|跳过 ipset 和 nftset 规则|
    |`-no-rule-soa`|跳过 SOA(#) 规则|
    |`-no-dualstack-selection`|停用双栈测速|
    |`-no-speed-check`|停用测速|
    |`-no-cache`|停止缓存|
    |`-force-aaaa-soa`|禁用IPV6查询|
    |`-no-ip-alias`|忽略ip集合规则|
    |`-ipset [ipsetname]`|将对应请求的结果放入指定ipset|
    |`-nftset [nftsetname]`|将对应的请求结果放入指定的nftset|
