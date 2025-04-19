---
hide:
  - toc
---

# 上游DNS服务器

SmartDNS提供了多种查询方式，目前支持的有，UDP、TCP、DOT、DOH、DOQ、DOH3，这些查询协议在性能，安全性上各有优缺点，可按需配置使用，
下表是几个协议的说明

配置参数|协议|性能|安全|公共服务器数量|说明
--|--|--|--|--|--
server|UDP|极好|差|多|通过UDP协议查询，0-RTT可以查询到结果，但安全性无保障。
server-tcp|TCP|好|差|多|通过TCP协议查询，需要三次握手，安全性也也不保证，主要用于UDP查询失败时的后备。
server-tls|DOT|一般|好|一般|通过TLS查询，需要TCP的三次握手和TLS的协议握手，性能差，但安全性有保障。
server-https|DOH|一般|好|一般|通过HTTPS查询，在TLS的基础上通过HTTP协议查询，好处是能使用现有的HTTP协议，兼容性好。
server-quic|DOQ|极好|好|非常少|通过Quic查询，性能，安全都有保障，但目前公共的服务器较少。
server-h3|DOH3|好|好|非常少|在Quic上增加HTTP协议，性能好，兼容性好，但目前公共服务器较少。

## 配置UDP服务器

1. 通过`server`参数配置，例子如下：

    ```shell
    # 常规配置
    server 1.1.1.1
    # URI形式的配置
    server udp://1.1.1.1
    # -g设置server分组，-g可以支持多个，可以同时归属多个分组
    server 1.1.1.1 -g group1 -g group2
    # -e|-exclude-default-group 将服务器从默认组中排除
    server 1.1.1.1 -e -g office
    ```

1. 常见参数说明:

    * `-g|-group`: 设置服务器所属的域名组，配合`nameserver /domain/group`，可实现对应域名使用指定的服务器查询，一个服务器可归属多个域名组，`-g`参数可以重复出现。
    * `-e|-exclude-default-group`: 从默认组中排除，所有上游服务器默认都会加入默认组，所有未设置分组的域名，都会使用默认组查询，为避免域名泄漏，可以设置此参数。
    * `-proxy`: 设置使用代理进行查询，配合`proxy-server`使用
    * `-b|-bootstrap-dns`: 设置DNS为bootstrap DNS，仅在解析域名类服务器的时候使用，如果为配置bootstrap-dns，系统将自动使用IP类的服务器子自解析域名。
    * `-interface`: 使用指定的端口进行查询。

    其他更多参数，请查看配置参数说明。

## 配置TCP服务器

1. 通过`server-tcp`配置tcp服务器，其基本参数和udp服务器一致，例子如下：

    ```shell
    # 常规配置
    server-tcp 1.1.1.1
    # URI形式的配置
    server tcp://1.1.1.1
    # 设置TCP链接超时时间。
    server-tcp 1.1.1.1 -tcp-keepalive 30
    ```

1. 常见参数说明:

    * `-tcp-keepalive `: 设置tcp连接空闲超时时间，单位秒，取决于服务器。
    * 其他基本参数同udp协议。

## 配置TLS服务器, DOT

1. 通过`server-tls`配置tls服务器，其基本参数和tcp服务器一致，例子如下：

    ```shell
    # 常规配置
    server-tls 1.1.1.1
    # 预先指定服务器IP，避免域名解析
    server-tls dns.google -host-ip 8.8.4.4
    # 校验远端服务器证书的SAN字段的域名是否合法。
    server-tls dns.google -tls-host-verify dns.google
    # 设置TLS中SNI的主机名称。
    server-tls 8.8.8.8 -host-name dns.google
    # 校验spki-pin
    server-tls 8.8.8.8 -spki-pin 3N9hMehDPwrM/PgifVYFZV4c3+H+GAKmhBDAtdoPgtA=
    # 不校验证书是否合法
    server-tls 8.8.8.8 -k
    ```

1. 常见参数说明:

    * `-host-ip`: 强制设置对应服务器域名的IP地址，避免进行二次解析。
    * `-tls-host-verify`: 校验证书中的SAN域名，CN域名是否合法。
    * `-host-name`: 强制指定TLS证书的SNI名称，`-`表示不发送SNI名称。
    * `-spki-pin`: 另外一种服务器合法性校验的方式，无需证书链。
    * `-k|-no-check-certificate`: 不校验证书是否合法，非特殊场景不建议使用，这会导致协议不安全。
    * 其他基本参数同tcp协议。


## 配置HTTPS服务器, DOH

1. 通过`server-https`配置https服务器，其基本参数和tls服务器一致，例子如下：

    ```shell
    # 常规配置
    server-https https://dns.google/dns-query
    # 指定HTTP协议的主机信息
    server-https 8.8.8.8 -host-name dns.google -http-host dns.google
    ```

1. 常见参数说明:

    * `-http-host`: 强制设置HTTP协议中的HOST字段，默认情况下，此值复制配置的上游服务器参数。
    * 其他基本参数同tls协议。

## 配置Quic服务器, DOQ

1. 通过`server-quic`配置DoQ服务器，其基本参数和tls服务器一致，例子如下：

    ```shell
    # 常规配置
    server-quic 223.5.5.5
    ```

1. 常见参数说明:

    * 基本参数同tls协议。

## 配置HTTP3服务器, DOH3

1. 通过`server-h3`配置DoH3服务器，其基本参数和https服务器一致，例子如下：

    ```shell
    # 常规配置
    server-h3 h3://dns.alidns.com/dns-query
    # 另外一种兼容写法
    server-http3 http3://dns-unfiltered.adguard.com/dns-query
    ```

1. 常见参数说明:

    * 基本参数同https协议。