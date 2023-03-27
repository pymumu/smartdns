---
hide:
  - toc
---

# Entware安装

## 准备

在使用此软件时，需要确认路由器是否支持 U 盘，并准备好 U 盘一个。

## 安装 SmartDNS

将软件（使用 WinSCP 等）上传到路由器的 `/tmp` 目录，执行如下命令安装

```shell
ipkg install smartdns.1.yyyy.MM.dd-REL.mipsbig.ipk
```

## 修改 SmartDNS 配置

- 配置文件

```shell
vi /opt/etc/smartdns/smartdns.conf
```

- `/opt/etc/smartdns/smartdns.conf`配置包含如下基本内容：

```shell
# 指定监听的端口号
bind []:53 
# 指定上游服务器
server 1.1.1.1
server-tls 8.8.8.8
# 指定域名规则
address /example.com/1.2.3.4
domain-rules /example.com/ -address 1.2.3.4
```

**注意：**

- 如需支持 IPv6，可设置工作模式为 `2`，将 DNSmasq 的 DNS 服务禁用，设置 SmartDNS 为主用 DNS 服务器。将文件 `/opt/etc/smartdns/smartdns-opt.conf` 中的 `SMARTDNS_WORKMODE` 的值修改为 `2`

```shell
SMARTDNS_WORKMODE="2"
```

## 重启路由器使服务生效

- 待路由器启动后， 执行

```shell
nslookup -querytype=ptr smartdns
```

- 查看命令结果中的 `name` 是否为 `smartdns` 或你的主机名，如果是则表示生效

```shell
$ nslookup -querytype=ptr smartdns
Server:         192.168.1.1
Address:        192.168.1.1#53

Non-authoritative answer:
smartdns        name = smartdns.
```

**注意：**

若服务没有自动启动，则需要设置 Optware / Entware 自动启动，具体方法请参考 Optware/Entware 的文档。
