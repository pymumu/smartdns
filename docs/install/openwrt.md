---
hide:
  - toc
---

# OpenWrt安装

将软件包（使用 WinSCP 等）上传到路由器的 `/root` 目录，执行如下命令安装

openwrt 24.10之后版本
```shell
apk add --allow-untrusted smartdns.1.yyyy.MM.dd-REL.xxxx.ipk
apk add --allow-untrusted luci-app-smartdns-lite.1.yyyy.MM.dd-REL.all.ipk
```

openwrt 24.10之前版本
```shell
opkg install smartdns.1.yyyy.MM.dd-REL.xxxx.ipk
opkg install luci-app-smartdns-lite.1.yyyy.MM.dd-REL.all.ipk
```

- **注意：** 19.07 之前的版本，请务必安装 `luci-app-smartdns.1.yyyy.MM.dd-REL.all-luci-compat-all.ipk`。

## 修改配置

登录 OpenWrt 管理页面，打开 `Services` -> `SmartDNS` 进行配置。

- 在 `Upstream Servers` 增加上游 DNS 服务器配置，建议配置多个国内外 DNS 服务器。
- 在 `Domain Address` 指定特定域名的 IP 地址，可用于广告屏蔽。

## 启用服务

- 替换默认Dnsmasq为主DNS。

登录 OpenWrt 管理界面，点击 `Services` -> `SmartDNS` -> `port`，设置端口号为`53`，smartdns会自动接管主DNS服务器。

- 检测转发服务是否配置成功

执行

```shell
nslookup -querytype=ptr smartdns
```

查看命令结果中的 `name` 是否为 `smartdns` 或你的主机名，如果是则表示生效

```shell
$ nslookup -querytype=ptr smartdns
Server:         192.168.1.1
Address:        192.168.1.1#53

Non-authoritative answer:
smartdns        name = smartdns.
```

## 启动服务

勾选配置页面中的 `Enable（启用）`来启动 SmartDNS。

## **注意：**

- 如已经安装 ChinaDNS，建议将 ChinaDNS 的上游配置为 SmartDNS。
- 当smartdns的端口为53时，将自动接管dnsmasq为主dns。配置其他端口时，会重新启用dnsmasq为主dns。
- 若在此过程中发生异常，可使用如下命令还原dnsmasq为主DNS

```shell
uci delete dhcp.@dnsmasq[0].port
uci commit dhcp
/etc/init.d/dnsmasq restart
```