---
hide:
  - toc
---

# 黑名单分流请求

## 分流流程

分流需要实现的功能如下：

* 内部域名从内部DNS服务器查询，并对IP进行测速，将最快IP地址返回客户端。
* 外部域名从外部服务器查询，外部域名通过域名列表管理，IP数据通过TPROXY进行透明转发。

对应的流程图如下：

``` mermaid
%%{init: {'theme':'forest'}}%%
flowchart 
    style client color:white,fill:#dd5555,stroke:#ee00,stroke-width:2px
    style ipset color:white,fill:green,stroke:#ee00,stroke-width:2px
    style ipset1 color:white,fill:green,stroke:#ee00,stroke-width:2px
    style speed-check color:white,fill:green,stroke:#ee00,stroke-width:2px
    client(((客户端)))-----> |1. 请求|smartdns
    smartdns---->|2. 获取到IP|client
    client--->|3. 使用IP请求数据|router
    subgraph smartdns [SmartDNS&nbsp&nbsp]
        server(DNS服务)-->|a. 处理规则namserver|rule(域名规则)
        rule-->|b. 外部域名|public-group(外部服务器组)
        rule-->|b. 内部域名|private-group(内部服务器组)
        public-group-->|d. IP加入IPSet|ipset1(IPSet,NFTSet)
        private-group-->|d. 测速获取最快IP|speed-check(测速)
    end
    router-->ipset(IPSet,NFTSet)
    subgraph router [路由网关]
        NAT-->|a. 收取数据包|ipset-->|b. 数据转发|tproxy(TPROXY转发服务)
    end
    tproxy----->|VPN|ProxyServer
    tproxy----->|SOCKS5|ProxyServer
    tproxy----->|HTTP PROXY|ProxyServer

    public-group--->|c. 查询外部域名|public-servers(外部DNS服务器)
    private-group--->|c. 查询内部域名|private-servers(内部DNS服务器)

```

  1. 客户端到SmartDNS服务器查询域名。
  1. SmartDNS处理请求。
    1. 根据namserver给定的规则判断域名
    1. 如果域名为内部域名，则使用内部域名服务器查询；如果域名为外部域名，则使用外部域名服务器查询。
        1. 内部域名，使用测速功能，获取最快IP地址。
        1. 外部域名，获取最快响应DNS结果后，将IP地址添加到IPSet/NFTSet中。
    1. SmartDNS返回IP地址。
  1. 客户端从SmartDNS获取到IP地址。
  1. 客户端使用IP地址通过网关请求数据。
  1. 网关接受到数据包，使用IPSet/NFTSet判断IP规则。
    1. 如果IP存在IPSet/NFTSet中（外部域名），则使用TPROXY将数据发送到远端代理服务器。
    1. 如果IP不存在IPSet/NFTSet中（内部域名），则直接NAT转发数据。

## SmartDNS分流配置

在上述流程图中，SmartDNS分流数据，需要做如下设置
  * 内部域名从内部DNS服务器查询，并对IP进行测速，将最快IP地址返回客户端。
  * 外部域名从外部服务器查询，不进行测速，将IP地址放入IPSet/NFTSet中供数据转发。

1. 基本配置

    启用SmartDNS服务，并设置相关的功能。

    ```shell
    # 启用服务器
    bind [::]:53
    # 启用测速
    speed-check-mode ping,tcp:80,tcp:443
    # 启用双栈优选
    dualstack-ip-selection yes
    # 启用缓存和持久化
    cache-size 32768
    cache-persist yes
    prefetch-domain yes
    serve-expired yes
    ```

1. 添加DNS服务器

    添加上游服务器，并通过`-group`参数指定内外服务器组。

    ```shell
    # 外部服务器组
    server 1.2.3.4 -group public

    # 内部服务器组
    server 1.2.3.4 -group private
    ```

    注意：  

    1. 推荐配置多个外部和内部服务器。
    1. public外部服务器组，可选择配置`-exclude-default-group`参数，避免内部域名通过外部服务器查询。
    1. public外部服务器组，可以使用`proxy-server`选项，配置通过socks5,http代理查询，这样结果会更好。

1. 配置域名规则

    配置黑名单域名，对名单中的域名走public服务器组，并关闭测速，关闭IPV6，加入IPSET。

    ```shell
    # 添加域名列表，格式为一行一个域名
    domain-set -name public-domain-list -file /path/to/public/domain/list
    # 设置对应域名列表的规则。
    domain-rules /domain-set:public-domain-list/ -ipset public  -nftset #4:ip#table#set -c none -address #6 -nameserver public
    ```

    注意：

    1. 域名列表可以配置crontab周期自动更新，其格式为一行一个域名。

        ```shell
        a.com
        b.com
        ...

        ```

    1. 域名规则中：
        1. -ipset: 表示添加结果到对应的ipset名称，`public`为例子，可按需修改为对应的ipset名称。
        1. -nftset: 表示添加结果到对应的nftset名称，`#4:ip#table#set`为例子，需要修改为对应的ipset名称。
        1. -c none: 表示禁用测速，具体参数参考speed-check-mode。
        1. -address #6: 表示禁用IPV6，如果转发程序支持IPV6，则可以不使用此参数。
        1. -nameserver public: 表示使用public组的DNS服务器解析结果。

## IPSET以及透明转发规则配置

为配合smartdns完成外部请求的转发，好需要配置相关的ipset，和规则。具体配置步骤如下：

1. 创建IPSet

    执行shell命令，创建IPSET。

    ```shell
    # 创建ipset集合
    ipset create public hash:net
    ```

1. 设置透明转发规则：

    Linux透明转发分为TPROXY和REDIRECT两种模式，这两种模式使用上有如下区别，可按需求选择配置。

    1. 模式：TPROXY，REDIRECT

        TPROXY：支持UDP，TCP的转发，配置稍复杂。  
        REDIRECT：仅支持TCP，配置简单。

    1. 方式一：仅TCP转发

    ```shell
    # 设置转发规则，将匹配的请求转发到本机的1081端口
    iptables -t nat -I PREROUTING -p tcp -m set --match-set public dst -j REDIRECT --to-ports 1081
    ```

    1. 方式二：TCP/UDP TPROXY转发
  
        执行shell命令，设置iptable规则，将匹配的域名TCP/UDP请求进行TPROXY方式透明转发，规则参考如下：

        ```shell
        # 设置路由规则
        ip rule add fwmark 1104 lookup 1104
        ip route add local 0.0.0.0/0 dev lo table 1104

        # 设置转发规则，UDP，TCP方式的TPROXY转发，将数据转发到本机的1081端口
        iptables -t mangle -N SMARTDNS
        iptables -t mangle -A SMARTDNS -p tcp -m set --match-set public dst -j TPROXY --on-ip 127.0.0.1 --on-port 1081 --tproxy-mark 1104
        iptables -t mangle -A SMARTDNS -p udp -m set --match-set public dst -j TPROXY --on-ip 127.0.0.1 --on-port 1081 --tproxy-mark 1104
        iptables -t mangle -A SMARTDNS -j ACCEPT
        iptables -t mangle -A PREROUTING -j SMARTDNS
        ```

## 本机1081端口启用转发程序

本机下载安装TPROXY模式的转发程序，并启用1081端口的数据查询服务。

## 额外说明

如果使用OpenWrt的luci界面，可以直接在界面配置相关的域名分流规则。
