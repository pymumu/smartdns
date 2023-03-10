---
hide:
  - navigation
---

# 常见问题

## SmartDNS 和 DNSmasq 有什么区别？

SmartDNS 在设计上并不是 DNSmasq 的替代品，它的主要功能集中在 DNS 解析增强上，增强部分有：

- 多上游服务器并发请求，对结果进行测速后，返回最佳结果；
- address、ipset 域名匹配采用高效算法，查询匹配更加快速，即使是路由器设备也依然高效；
- 域名匹配支持忽略特定域名，可单独匹配 IPv4 和 IPv6，支持多样化定制；
- 针对广告屏蔽功能做增强，返回 SOA，屏蔽广告效果更佳；
- IPv4、IPv6 双栈 IP 优选机制，在双网情况下，选择最快的网络通讯；
- 支持最新的 TLS 和 HTTPS 协议，提供安全的 DNS 查询能力；
- ECS 支持，使查询结果更佳准确；
- IP 黑名单和忽略 IP 机制，使域名查询更佳准确；
- 域名预查询，访问常用网站更加快速；
- 域名 TTL 可指定，使访问更快速；
- 高速缓存机制，使访问更快速；
- 异步日志，审计机制，在记录信息的同时不影响 DNS 查询性能；
- 域名组（group）机制，特定域名使用特定上游服务器组查询，避免隐私泄漏；
- 第二 DNS 支持自定义更多行为。

## 如何配置上游服务器最佳？

SmartDNS 有测速机制，在配置上游服务器时，建议配置多个上游 DNS 服务器，包含多个不同区域的服务器，但总数建议在 10 个左右。推荐搭配

- 运营商 DNS。
- 国内公共 DNS，如 `119.29.29.29`, `223.5.5.5`。
- 国外公共 DNS，如 `8.8.8.8`, `8.8.4.4`。

## 如何启用审计日志？

审计日志记录客户端请求的域名，记录信息包括，请求时间，请求 IP，请求域名，请求类型，如果要启用审计日志，在配置界面配置 `audit-enable yes` 启用，`audit-size`、 `audit-file`、`audit-num` 分别配置审计日志文件大小，审计日志文件路径，和审计日志文件个数。审计日志文件将会压缩存储以节省空间。

## 如何避免隐私泄漏？

默认情况下，SmartDNS 会将请求发送到所有配置的DNS服务器，若上游 DNS 服务器使用DNS，或记录日志，将会导致隐私泄漏。为避免隐私泄漏，请尽量：  

- 配置使用可信的DNS服务器。
- 优先使用 TLS 查询。
- 设置上游 DNS 服务器组。

## 如何屏蔽广告？

SmartDNS 具备高性能域名匹配算法，通过域名方式过滤广告非常高效，如要屏蔽广告，只需要配置类似如下记录即可，如，屏蔽 `*.ad.com`，则配置：

```shell
address /ad.com/#
```

域名的使后缀模式，过滤 `*.ad.com`，`#` 表示返回 SOA，使屏蔽广告更加高效，如果要单独屏蔽 IPv4 或 IPv6， 在 `#` 后面增加数字，如 `#4` 表示对 IPv4 生效。若想忽略特定子域名的屏蔽，如忽略 `pass.ad.com`，可配置如下：

```shell
address /pass.ad.com/-
```

## 如何使用 DNS 查询分流？

某些情况下，需要将有些域名使用特定的 DNS 服务器来查询来做到 DNS 分流。比如

```shell
.home -> 192.168.1.1 # .home 结尾的域名发送到 192.168.1.1 解析
.office -> 10.0.0.1  # .office 结尾的域名发送到 10.0.0.1 解析
```

其他域名采用默认的模式解析。
这种情况的分流配置如下：

```shell
# 配置上游，用 -group 指定组名，用 -exclude-default-group 将服务器从默认组中排除。
server 192.168.1.1 -group home -exclude-default-group
server 10.0.0.1 -group office -exclude-default-group
server 8.8.8.8

# 配置解析的域名
nameserver /.home/home
nameserver /.office/office
```

通过上述配置即可实现 DNS 解析分流，如果需要实现按请求端端口分流，可以配置第二 DNS 服务器，`bind` 配置增加 `--group` 参数指定分流名称。

```shell
bind :7053 -group office
bind :8053 -group home
```

## IPv4、IPv6 双栈 IP 优选功能如何使用？

目前 IPv6 已经开始普及，但 IPv6 网络在速度上，某些情况下还不如 IPv4。为在双栈网络下获得较好的体验，SmartDNS 提供来双栈IP优选机制，同一个域名，若 IPv4 的速度远快与 IPv6，那么 SmartDNS 就会阻止IPv6的解析、使用 IPv4 访问。可在配置文件中通过设置 `dualstack-ip-selection yes` 启用此功能，通过 `dualstack-ip-selection-threshold [time]` 来修改阈值。如果要完全禁止 IPv6 AAAA记录解析，可设置 `force-AAAA-SOA yes`。

## 如何提高缓存效率，加快访问速度？

SmartDNS 提供了域名缓存机制，对查询的域名，进行缓存，缓存时间符合 DNS TTL 规范。为提高缓存命中率，可采用如下措施：  

- 适当增大缓存的记录数

    通过 `cache-size` 来设置缓存记录数。  

    查询压力大的环境下，并且有内存大的机器的情况下，可适当调大。  

- 适当设置最小 TTL 值

    通过 `rr-ttl-min` 将最低 DNS TTL 时间设置为一个合理值，延长缓存时间。

    建议是超时时间设置在 10～30 分钟，避免服务器域名变化时，查询到失效域名。

- 开启域名预获取功能

    通过 `prefetch-domain yes` 来启用域名预先获取功能，提高查询命中率。

    配合上述 TTL 超时时间，SmartDNS 将在域名 TTL 即将超时时，再次发送查询请求，并缓存查询结果供后续使用。频繁访问的域名将会持续缓存。此功能将在空闲时消耗更多的 CPU。

- 过期缓存服务功能  

    通过 `serve-expired` 来启用过期缓存服务功能，可提高缓存命中率的同时，降低CPU占用。

    此功能会在TTL超时后，将返回 TTL=0 给客户端，并且同时再次发送查询请求，并缓存新的结果给后续使用。

## 第二 DNS 如何自定义更多行为？

第二 DNS 可以作为其他 DNS 服务器的上游，提供更多的查询行为，通过 bind 配置支持可以绑定多个端口，不同端口可设置不同的标志，实现不同的功能，如

```shell
# 绑定 6053 端口，6053 端口的请求将采用配置 office 组的上游查询，且不对结果进行测速，忽略 address 的配置地址
bind [::]:6053 -no-speed-check -group office -no-rule-addr
```

## DoT 的 SPKI 如何获取？

SPKI 可以通过 DNS 服务商发布的页面获取，如果没有发布，可以通过如下命令获取，其中将对应IP地址更换为要获取 SPKI 的 IP 地址。

```shell
echo | openssl s_client -connect '1.0.0.1:853' 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

## iOS系统解析缓慢问题怎么解决？  

IOS14开始，苹果支持了DNS HTTPS(TYPE65)记录的解析，此功能用于快速DNS查询和解决HTTPS链接相关的问题，但当前还是草案，另外会导致广告屏蔽等功能失效，建议通过如下配置关闭TYPE65记录查询。

```shell
force-qtype-SOA 65
```

## 如何解析本地主机名称？  

smartdns可以配合DNSMASQ的dhcp lease文件支持本地主机名->IP地址的解析，可以配置smartdns读取dnsmasq的lease文件，并支持解析。具体配置参数如下，（注意，DNSMASQ lease文件每个系统可能不一样，需要按实际情况配置）

```shell
dnsmasq-lease-file /var/lib/misc/dnsmasq.leases
```

配置完成后，可以直接使用主机名连接对应的机器。但需要注意：

- Windows系统默认使用mDNS解析地址，如需要在windows下用使用smartdns解析，则需要在主机名后面增加`.`，表示使用DNS解析。如`ping smartdns.`

## 域名集合如何使用？  

为方便按集合配置域名，对于有/domain/的配置，可以指定域名集合，方便维护。具体方法为：

- 使用`domain-set`配置集合文件，如

```shell
domain-set -name ad -file /etc/smartdns/ad-list.conf
```

ad-list.conf的格式为一个域名一行，如

```shell
ad.com
site.com
```

- 在有/domain/配置的选项使用域名集合，只需要将`/domain/`配置为`/domain-set:[集合名称]/`即可，如：

```shell
address /domain-set:ad/#
domain-rules /domain-set:ad/ -a #
nameserver /domain-set:ad/server
...
```

## 如何使用ipset和nftset  

和Dnsmasq类似，smartdns支持ipset和nftset，可以将特定的域名通过TPROXY进行透明转发，透明转发涉工具模式对比如下：

1. 工具：iptable，nftable

    iptable：成熟的路由规则配置工具。  
    nftable：更加强大的规则配置工具，正在成为主流。

1. 模式：TPROXY，REDIRECT

    TPROXY：支持UDP，TCP的转发，配置稍复杂。  
    REDIRECT：仅支持TCP，配置简单。

1. 配置REDIRECT或TPROXY转发规则

    在smartdns.conf中设置需要透明转发的域名列表，比如要将`example.com`进行透明转发。则使用ipset选项，设置`example.com`的ipset规则为`proxy`。

    ```shell
    # 设置规则
    # -ipset proxy: 匹配的域名设置到ipset:tproxy中。
    # -c none: 停用测速
    # -address #6: 停用IPV6解析。
    domain-rules /example.com/ -ipset proxy -c none -address #6
    ```

    1. 方式一: TCP REDIRECT转发

        - 此方式配置简单，仅支持TCP的转发。  
            执行shell命令，设置iptable规则，如果仅转发TCP则可以直接使用REDIRECT的规则，如果需要同时转发UDP和TCP，可以使用TPROXY的转发规则。如下规则按实际需求选择。具体配置如下：

        ```shell
        # 创建ipset集合
        ipset create proxy hash:net
        # 设置转发规则，将匹配的请求转发到本机的1081端口
        iptables -t nat -I PREROUTING -p tcp -m set --match-set proxy dst -j REDIRECT --to-ports 1081
        ```

        - 在本机1081端口开启REDIRECT模式的转发程序。

    1. 方式二：TCP/UDP TPROXY转发

        - 此方式可同时转发TCP和UDP。  
            执行shell命令，设置iptable规则，将匹配的域名TCP/UDP请求进行TPROXY方式透明转发，规则参考如下：

        ```shell
        # 设置路由规则
        ip rule add fwmark 1104 lookup 1104
        ip route add local 0.0.0.0/0 dev lo table 1104

        # 创建ipset集合
        ipset create proxy hash:net

        # 设置转发规则，UDP，TCP方式的TPROXY转发
        iptables -t mangle -N SMARTDNS
        iptables -t mangle -A SMARTDNS -p tcp -m set --match-set proxy dst -j TPROXY --on-ip 127.0.0.1 --on-port 1081 --tproxy-mark 1104
        iptables -t mangle -A SMARTDNS -p udp -m set --match-set proxy dst -j TPROXY --on-ip 127.0.0.1 --on-port 1081 --tproxy-mark 1104
        iptables -t mangle -A SMARTDNS -j ACCEPT
        iptables -t mangle -A PREROUTING -j SMARTDNS
        ```

        - 在本机的1081端口启动IP透明转发程序。

1. 额外说明  

    - 为保证DNS查询结果的位置亲和性，可以使用smartdns的`server`代理参数，将对应域名的查询请求，通过代理查询，使结果位置更好。如：

    ```shell
    # 增加DNS上游，并设置通过名称为proxy的代理查询，查询组为pass
    server 1.2.3.4 -proxy proxy -group pass -exclude-default-group
    # 设置代理服务器信息，代理的名称为proxy
    proxy-server socks5://user:name@1.2.3.4 -name proxy
    # 设置域名规则，对匹配的域名使用代理查询结果，并将结果设置到ipset中。
    domain-rules /example.com/ -ipset proxy -c none -address #6 -nameserver pass
    ```

    - 如需要配合测速自动完成ipset的设置，可增加如下配置参数

    ```shell
    ipset-no-speed proxy
    ```

如果使用OpenWrt的luci界面，可以直接在界面配置相关的域名分流规则。

## BootStrap DNS  

对于域名类的上游服务器，SmartDNS会使用其他IP地址类的服务器进行解析，所以一般情况下无需配置BootStrap DNS，但如果有特殊需求，需要指定BootStrap DNS。则可以通过如下方式配置：

1. nameserver指定上游服务器  

    使用nameserver参数指定特定域名使用指定DNS解析。

    ```shell
    server dns.server # 此服务器将使用1.2.3.4解析。
    server 1.2.3.4 -group bootstrap
    nameserver /dns.server/bootstrap
    ```

1. 对所有服务器指定bootstrap DNS。  

    使用`-bootstrap-dns`参数，指定特定的server为bootstrap DNS。  

    ```shell
    server 1.2.3.4 -bootstrap-dns
    server dns.server
    ```

## 更多问题

如有更多问题，请查阅或提交issue: [https://github.com/pymumu/smartdns/issues](https://github.com/pymumu/smartdns/issues)