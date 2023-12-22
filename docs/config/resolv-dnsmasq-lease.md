---
hide:
  - toc
---

# 解析本地主机名称

## 使用DNSMASQ lease文件

smartdns可以配合DNSMASQ的dhcp lease文件支持本地主机名->IP地址的解析，可以配置smartdns读取dnsmasq的lease文件，并支持解析。具体配置参数如下  
（注意，DNSMASQ lease文件每个系统可能不一样，需要按实际情况配置）

```shell
dnsmasq-lease-file /var/lib/misc/dnsmasq.leases
```

配置完成后，可以直接使用主机名连接对应的机器。但需要注意：

1. Windows系统默认使用mDNS解析地址，如需要在windows下用使用smartdns解析，则需要在主机名后面增加`.`，表示使用DNS解析。如`ping smartdns.`
1. smartdns会周期监控文件变化，并自动加载变化的映射关系。

## 使用mDNS查询

smartdns可以使用mDNS，来查询本地主机名或IP地址。具体配置如下

```shell
mdns-lookup yes
```
