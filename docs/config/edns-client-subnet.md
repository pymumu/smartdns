---
hide:
  - toc
---

# EDNS客户端子网

SmartDNS提供了设置`edns-client-subnet`的能力，edns-client-subnet原本功能是用于上游DNS服务器之间的一个扩展通信协议。一般情况下本地DNS无需配置。

但SmartDNS提供了测速和通过代理查询的能力，在下面的场景下，则可设置edns-client-subnet优化网络查询结果：

## 跨运营商的IP优化

运营商的DNS服务器都是将自己网络的网站或CDN服务器IP给客户端，比如qq.com，用联通的DNS，查询的就是联通网段的IP，你用电信的，查询的就是电信网段的IP。运营商一般不会给你跨网IP。除非某个网站就只有在某个运营商的网络。但某些网站，运营商自己网络的ip可能要跨好几个省，时延比较大，不如同省跨运营商去访问。这时可以通过edns-client-subnet能力，查询到一个异网的IP，然后再让smartdns测速后，返回时延较小的IP给客户端。

### 配置

假设你的宽带是广东联通。那么你可以配置如下：

```shell
server 8.8.8.8 -subnet [广东电信IP]
```

这样8.8.8.8就会返回网站为广东电信网段的IP地址，smartdns会根据测速结果返回IP给客户端。
-subnet ipv4，和ipv6都配置。

网段信息[http://ipcn.chacuo.net/](http://ipcn.chacuo.net)

## 通过代理查询

当smartdns通过代理查询时，对应的查询结果是根据代理服务器出口优化的查询结果，如果想要通过代理查询的结果和本地运营商优化，则可以通过配置edns-client-subnet来优化。

### 配置

假设广东电信的用户通过北京的代理查询DNS，那么可以配置如下

```shell
server 8.8.8.8 -proxy beijing -subnet [广东电信IP]
```

这样即使通过北京代理到8.8.8.8查询结果，但因为指定了客户端子网为广东电信IP，那么8.8.8.8就会范围合适广东电信网络的IP地址。
