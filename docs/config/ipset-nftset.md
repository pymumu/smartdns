---
hide:
  - toc
---

# 使用ipset和nftset  

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
