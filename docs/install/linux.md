---
hide:
  - toc
---

# Linux安装

- 下载配套安装包，并上传到 Linux 系统中, 标准 Linux 系统（X86 / X86_64）请执行如下命令安装：

```shell
tar zxf smartdns.1.yyyy.MM.dd-REL.x86_64-linux-all.tar.gz
cd smartdns
chmod +x ./install
./install -i
```

- 树莓派或其他 Debian 系系统（ARM / ARM64）请执行如下命令安装：

```shell
dpkg -i smartdns.1.yyyy.MM.dd-REL.arm-debian-all.deb
```

**注意**

  1. ubuntu系统下，`systemd-resolved`会占用TCP53和UDP53端口, 你需要手动解决端口占用问题或者修改smartdns监听端口。
  1. 日志文件在`/var/log/smartdns/smartdns.log`

## 修改配置

安装完成后，可配置 SmartDNS 的上游服务器信息，一般情况下，只需要增加 `server`[`IP`]`:port` 和 `server-tcp`[`IP`]`:port` 配置项，请尽可能配置多个上游 DNS 服务器，包括国内外的服务器。具体配置参数请参考`配置文件`说明

- 配置文件

```shell
vi /etc/smartdns/smartdns.conf
```

`/etc/smartdns/smartdns.conf`配置包含如下基本内容：

```shell
# 指定监听的端口号
bind []:53 
# 指定上游服务器
server 1.1.1.1
server-tls 8.8.8.8
# 指定域名规则
address /example.com/1.2.3.4
domain-rule /example.com/ -address 1.2.3.4
```

## 启动服务

```shell
systemctl enable smartdns
systemctl start smartdns
```

## 将 DNS 请求转发到 SmartDNS 解析

修改本地路由器的 DNS 服务器，将 DNS 服务器配置为 SmartDNS。

- 登录到本地网络的路由器中，配置树莓派，分配其静态 IP 地址。
- 修改 WAN 口或者 DHCP DNS 为树莓派 IP 地址。

    **注意：**  
    1. 每款路由器配置方法不尽相同，请在网络上搜索对应配置方法。
    1. 华为等路由器可能不支持配置 DNS 为本地 IP，可修改电脑端或手机端的 DNS 服务器为树莓派 IP。

## 检测服务是否配置成功

- 执行

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
