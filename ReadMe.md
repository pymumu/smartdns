# SmartDNS

**[English](ReadMe_en.md)**

![SmartDNS](doc/smartdns-banner.png)
SmartDNS 是一个运行在本地的 DNS 服务器，它接受来自本地客户端的 DNS 查询请求，然后从多个上游 DNS 服务器获取 DNS 查询结果，并将访问速度最快的结果返回给客户端，以此提高网络访问速度。
SmartDNS 同时支持指定特定域名 IP 地址，并高性匹配，可达到过滤广告的效果; 支持DOT(DNS over TLS)和DOH(DNS over HTTPS)，更好的保护隐私。  

与 DNSmasq 的 all-servers 不同，SmartDNS 返回的是访问速度最快的解析结果。

支持树莓派、OpenWrt、华硕路由器原生固件和 Windows 系统等。

## 使用指导

SmartDNS官网：[https://pymumu.github.io/smartdns](https://pymumu.github.io/smartdns)

## 软件效果展示

**阿里 DNS**  
使用阿里 DNS 查询百度IP，并检测结果。  

```shell
$ nslookup www.baidu.com 223.5.5.5
Server:         223.5.5.5
Address:        223.5.5.5#53

Non-authoritative answer:
www.baidu.com   canonical name = www.a.shifen.com.
Name:   www.a.shifen.com
Address: 180.97.33.108
Name:   www.a.shifen.com
Address: 180.97.33.107

$ ping 180.97.33.107 -c 2
PING 180.97.33.107 (180.97.33.107) 56(84) bytes of data.
64 bytes from 180.97.33.107: icmp_seq=1 ttl=55 time=24.3 ms
64 bytes from 180.97.33.107: icmp_seq=2 ttl=55 time=24.2 ms

--- 180.97.33.107 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 24.275/24.327/24.380/0.164 ms
pi@raspberrypi:~/code/smartdns_build $ ping 180.97.33.108 -c 2
PING 180.97.33.108 (180.97.33.108) 56(84) bytes of data.
64 bytes from 180.97.33.108: icmp_seq=1 ttl=55 time=31.1 ms
64 bytes from 180.97.33.108: icmp_seq=2 ttl=55 time=31.0 ms

--- 180.97.33.108 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 31.014/31.094/31.175/0.193 ms
```

**SmartDNS**  
使用 SmartDNS 查询百度 IP，并检测结果。

```shell
$ nslookup www.baidu.com
Server:         192.168.1.1
Address:        192.168.1.1#53

Non-authoritative answer:
www.baidu.com   canonical name = www.a.shifen.com.
Name:   www.a.shifen.com
Address: 14.215.177.39

$ ping 14.215.177.39 -c 2
PING 14.215.177.39 (14.215.177.39) 56(84) bytes of data.
64 bytes from 14.215.177.39: icmp_seq=1 ttl=56 time=6.31 ms
64 bytes from 14.215.177.39: icmp_seq=2 ttl=56 time=5.95 ms

--- 14.215.177.39 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 5.954/6.133/6.313/0.195 ms
```

从对比看出，SmartDNS 找到了访问 www.baidu.com 最快的 IP 地址，比阿里 DNS 速度快了 5 倍。

## 特性

1. **多虚拟DNS服务器**  
   支持多个虚拟DNS服务器，不同虚拟DNS服务器不同的端口，规则，客户端。

1. **多 DNS 上游服务器**  
   支持配置多个上游 DNS 服务器，并同时进行查询，即使其中有 DNS 服务器异常，也不会影响查询。  

1. **支持每个客户端独立控制**  
   支持基于MAC，IP地址控制客户端使用不同查询规则，可实现家长控制等功能。  

1. **返回最快 IP 地址**  
   支持从域名所属 IP 地址列表中查找到访问速度最快的 IP 地址，并返回给客户端，提高网络访问速度。

1. **支持多种查询协议**  
   支持 UDP、TCP、DOT 和 DOH 查询及服务，以及非 53 端口查询；支持通过socks5，HTTP代理查询;

1. **特定域名 IP 地址指定**  
   支持指定域名的 IP 地址，达到广告过滤效果、避免恶意网站的效果。

1. **域名高性能后缀匹配**  
   支持域名后缀匹配模式，简化过滤配置，过滤 20 万条记录时间 < 1ms。

1. **域名分流**  
   支持域名分流，不同类型的域名向不同的 DNS 服务器查询，支持iptable和nftable更好的分流；支持测速失败的情况下设置域名结果到对应ipset和nftset集合。

1. **Windows / Linux 多平台支持**  
   支持标准 Linux 系统（树莓派）、OpenWrt 系统各种固件和华硕路由器原生固件。同时还支持 WSL（Windows Subsystem for Linux，适用于 Linux 的 Windows 子系统）。

1. **支持 IPv4、IPv6 双栈**  
   支持 IPv4 和 IPV 6网络，支持查询 A 和 AAAA 记录，支持双栈 IP 速度优化，并支持完全禁用 IPv6 AAAA 解析。

1. **支持DNS64**  
   支持DNS64转换。

1. **高性能、占用资源少**  
   多线程异步 IO 模式，cache 缓存查询结果。

1. **主流系统官方支持**  
   主流路由系统官方软件源安装smartdns。

## 架构

![Architecture](https://github.com/pymumu/test/releases/download/blob/architecture.png)

1. SmartDNS 接收本地网络设备的DNS 查询请求，如 PC、手机的查询请求；
1. 然后将查询请求发送到多个上游 DNS 服务器，可支持 UDP 标准端口或非标准端口查询，以及 TCP 查询；
1. 上游 DNS 服务器返回域名对应的服务器 IP 地址列表，SmartDNS 则会检测从本地网络访问速度最快的服务器 IP；
1. 最后将访问速度最快的服务器 IP 返回给本地客户端。

## 编译

- 代码编译：

  SmartDNS 提供了编译软件包的脚本（`package/build-pkg.sh`），支持编译 LuCI、Debian、OpenWrt 和 Optware 安装包。

- 文档编译：

  文档分支为`doc`，安装`mkdocs`工具后，执行`mkdocs build`编译。

## 捐赠

如果你觉得此项目对你有帮助，请捐助我们，使项目能持续发展和更加完善。

### PayPal 贝宝

[![Support via PayPal](https://cdn.rawgit.com/twolfson/paypal-github-button/1.0.0/dist/button.svg)](https://paypal.me/PengNick/)

### AliPay 支付宝

![alipay](doc/alipay_donate.jpg)

### WeChat Pay 微信支付

![wechat](doc/wechat_donate.jpg)

## 开源声明

SmartDNS 基于 GPL V3 协议开源。
