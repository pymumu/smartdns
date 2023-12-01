---
hide:
  - toc
---

# 使用ipset和nftset  

和Dnsmasq类似，smartdns支持ipset和nftset，可以将特定的域名通过TPROXY进行透明转发，透明转发涉工具模式对比如下：

1. 工具：iptable，nftable

    iptable：成熟的路由规则配置工具。  
    nftable：更加强大的规则配置工具，正在成为主流。

## ipset配置

1. 基本配置

    通过如下参数可以配置指定域名的NFTSet规则

    ```shell
    ipset /domain/ipset
    ipset /domain/[#4:ipsetv4,#6:ipsetv6]
    ```

1. 超时

    SmartDNS设置IPSet，支持设置是否启用超时功能，这样可以避免NFTSet中过多IP地址，网关性能下降。启用方式为

    ```shell
    ipset-timeout yes
    ```

1. 测速失败后，自动添加到IPSet

    SmartDNS可以将测速失败的IP地址，加入IPSet，再由相关IP规则转发

    ```shell
    ipset-no-speed ipsetname
    ```

## nftset配置

1. 基本配置

    通过如下参数可以配置指定域名的IPSet规则

    ```shell
    nftset /domain/[#4:ip#table#set,#6:ipv6#table#setv6]
    ```

1. 超时

    SmartDNS设置IPSet，支持设置是否启用超时功能，这样可以避免IPSet中过多IP地址，网关性能下降。启用方式为

    ```shell
    nftset-timeout yes
    ```

1. 测速失败后，自动添加到IPSet

    SmartDNS可以将测速失败的IP地址，加入IPSet，再由相关IP规则转发

    ```shell
    nftset-no-speed ipsetname
    ```

1. DEBUG调试

    如需要Debug调试，可以开启nftset的调试功能。

    ```shell
    nftset-debug yes
    ```

## 对特定的服务端口设置ipset和nftset

smartdns的bind参数，支持设置ipset和nftset，当设置了ipset和nftset的端口接收到请求后，将对此端口的查询请求设置ipset和nftset。

通过如下配置，可以将对于端口的查询请求，全部设置到ipset中，比如将第二DNS的所有查询结果，放入ipset。

```shell
bind [::]:6053 -ipset [ipset] -nftset [nftset]
```

* -ipset：参数选项参考ipset选项。
* -nftset：选项参考nftset。
