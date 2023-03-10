---
hide:
  - toc
---

# Asus固件 / 梅林固件安装

**说明：**

梅林固件派生自华硕固件，理论上可以直接使用华硕配套的安装包使用。但目前未经验证，如有问题，请提交 Issue。

## 准备

在使用此软件时，需要确认路由器是否支持 U 盘，并准备好 U 盘一个。

## 启用 SSH 登录

登录管理界面，点击 `系统管理` -> `系统设置`，配置 `Enable SSH` 为 `Lan Only`。  
SSH 登录用户名密码与管理界面相同。

## 下载 `Download Master`

在管理界面点击 `USB 相关应用` -> `Download Master` 下载。  
下载完成后，启用 `Download Master`，如果不需要下载功能，此时可以卸载 `Download Master`，但要保证卸载前 `Download Master` 是启用的。  

## 安装 SmartDNS

- 将软件包（使用 WinSCP 等）上传到路由器的 `/tmp/mnt/sda1` 目录（或网上邻居复制到 sda1 共享目录），执行如下命令安装

```shell
ipkg install smartdns.1.yyyy.MM.dd-REL.mipsbig.ipk
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

## 额外说明

上述过程，SmartDNS 将安装到 U 盘根目录，采用 OptWare 的模式运行。
其目录结构如下（此处仅列出 SmartDNS 相关文件）：

```shell
U 盘
└── asusware.mipsbig
        ├── bin
        ├── etc
        |    ├── smartdns
        |    |     └── smartdns.conf
        |    └── init.d
        |          └── S50smartdns
        ├── lib
        ├── sbin
        ├── usr
        |    └── sbin
        |          └── smartdns
        ....
```

- 如要修改配置，可以 SSH 登录路由器，使用 vi 命令修改

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
domain-rule /example.com/ -address 1.2.3.4
```

- 也可以通过网上邻居修改，网上邻居共享目录 `sda1` 看不到 `asusware.mipsbig` 目录，但可以直接在`文件管理器`中输入 `asusware.mipsbig\etc\init.d` 访问

```shell
\\192.168.1.1\sda1\asusware.mipsbig\etc\init.d
```
