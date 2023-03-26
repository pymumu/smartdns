---
hide:
  - toc
---

# IP规则

smartdns提供了IP地址黑白名单和忽略相关的结果。

|参数|功能|使用场景|
|---|---|---|
|whitelist-ip|白名单 IP 地址|接受在指定范围内的IP地址设置
|blacklist-ip|黑名单 IP 地址|接受在指定范围外的IP地址设置
|ignore-ip|忽略 IP 地址|不需要某个IP地址，或IP地址段时设置。
|bogus-nxdomain|假冒 IP 地址过滤|请求结果包含对应IP地址时，返回SOA

## 白名单IP地址

如果想对某个上游限制其返回的IP地址在白名单范围，非白名单的地址全部丢弃，则可以设置如下：

```shell
server -whitelist-ip
whitelist-ip 192.168.1.1/24
```

## 黑名单IP地址

```shell
server -blacklist-ip
blacklist-ip 192.168.1.1/24
```

## 忽略IP地址

如果希望使用上游返回的某个IP地址，可以配置忽略此IP。

```shell
ignore-ip 1.2.3.4
```

## 假冒IP地址

如果网站不存在时，被ISP固定返回某个网段的IP地址的404页面，则可以使用此参数；比如电信的自定义404页面。则可以通过如下配置，让客户端接受到SOA，而不是被重定向的ISP的404页面。

```shell
bogus-nxdomain 1.2.3.4
```
