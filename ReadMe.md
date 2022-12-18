# SmartDNS

**[English](ReadMe_en.md)**

![SmartDNS](doc/smartdns-banner.png)
SmartDNS 是一个运行在本地的 DNS 服务器，它接受来自本地客户端的 DNS 查询请求，然后从多个上游 DNS 服务器获取 DNS 查询结果，并将访问速度最快的结果返回给客户端，以此提高网络访问速度。
SmartDNS 同时支持指定特定域名 IP 地址，并高性匹配，可达到过滤广告的效果; 支持DOT(DNS over TLS)和DOH(DNS over HTTPS)，更好的保护隐私。
与 DNSmasq 的 all-servers 不同，SmartDNS 返回的是访问速度最快的解析结果。详细差异请看[常见问题](#常见问题)。

支持树莓派、OpenWrt、华硕路由器原生固件和 Windows 系统等。  

## 目录

- [SmartDNS](#smartdns)
  - [目录](#目录)
  - [软件效果展示](#软件效果展示)
  - [特性](#特性)
  - [架构](#架构)
  - [下载](#下载)
    - [使用官方安装源](#使用官方安装源)
    - [手工下载安装](#手工下载安装)
  - [安装和使用](#安装和使用)
    - [标准 Linux 系统 / 树莓派](#标准-linux-系统--树莓派)
    - [OpenWrt](#openwrt)
    - [华硕路由器原生固件 / 梅林固件](#华硕路由器原生固件--梅林固件)
    - [Optware / Entware](#optware--entware)
    - [WSL](#wsl)
  - [配置文件说明](#配置文件说明)
  - [常见问题](#常见问题)
  - [编译](#编译)
  - [捐赠](#捐赠)
    - [PayPal 贝宝](#paypal-贝宝)
    - [AliPay 支付宝](#alipay-支付宝)
    - [WeChat Pay 微信支付](#wechat-pay-微信支付)
  - [开源声明](#开源声明)

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

1. **多 DNS 上游服务器**  
   支持配置多个上游 DNS 服务器，并同时进行查询，即使其中有 DNS 服务器异常，也不会影响查询。  

2. **返回最快 IP 地址**  
   支持从域名所属 IP 地址列表中查找到访问速度最快的 IP 地址，并返回给客户端，提高网络访问速度。

3. **支持多种查询协议**  
   支持 UDP、TCP、DOT 和 DOH 查询，以及非 53 端口查询。

4. **特定域名 IP 地址指定**  
   支持指定域名的 IP 地址，达到广告过滤效果、避免恶意网站的效果。

5. **域名高性能后缀匹配**  
   支持域名后缀匹配模式，简化过滤配置，过滤 20 万条记录时间 < 1ms。

6. **域名分流**  
   支持域名分流，不同类型的域名向不同的 DNS 服务器查询，支持iptable和nftable更好的分流。

7. **Windows / Linux 多平台支持**  
   支持标准 Linux 系统（树莓派）、OpenWrt 系统各种固件和华硕路由器原生固件。同时还支持 WSL（Windows Subsystem for Linux，适用于 Linux 的 Windows 子系统）。

8. **支持 IPv4、IPv6 双栈**  
   支持 IPv4 和 IPV 6网络，支持查询 A 和 AAAA 记录，支持双栈 IP 速度优化，并支持完全禁用 IPv6 AAAA 解析。

9. **高性能、占用资源少**  
   多线程异步 IO 模式，cache 缓存查询结果。

10. **主流系统官方支持**
   主流路由系统官方软件源安装smartdns。

## 架构

![Architecture](https://github.com/pymumu/test/releases/download/blob/architecture.png)

1. SmartDNS 接收本地网络设备的DNS 查询请求，如 PC、手机的查询请求；
2. 然后将查询请求发送到多个上游 DNS 服务器，可支持 UDP 标准端口或非标准端口查询，以及 TCP 查询；
3. 上游 DNS 服务器返回域名对应的服务器 IP 地址列表，SmartDNS 则会检测从本地网络访问速度最快的服务器 IP；
4. 最后将访问速度最快的服务器 IP 返回给本地客户端。

## 下载

### 使用官方安装源

smartdns已经合入主流系统的软件仓库，可以直接使用系统安装命令直接安装。

系统|安装方式|说明|
--|--|--
openwrt|opkg update<br>opkg install luci-app-smartdns<br>opkg install smartdns|22.03之后的系统。软件源路径：https://downloads.openwrt.org/releases/
ddwrt|官方最新固件service页面->SmartDNS Resolver->启用。|选择界面参考：https://forum.dd-wrt.com/demo/Services.html
debian|apt-get install smartdns|
entware|ipkg update<br>ipkg install smartdns|软件源路径：https://bin.entware.net/

### 手工下载安装

--------------

下载对应系统或固件版本的 SmartDNS 安装包，对应关系如下。

| 支持系统（架构） | 安装包 | 支持说明 |
| :--- | :--- | :--- |
| 标准 Linux 系统（ARM） | smartdns.1.yyyy.MM.dd-REL.arm-debian-all.deb | ARM 的树莓派 Raspbian Stretch 和 Debian 9 系统 |
| 标准 Linux 系统（ARM64） | smartdns.1.yyyy.MM.dd-REL.aarch64-debian-all.deb | ARM64 的 Debian Stretch 和 Debian 9 系统 |
| 标准 Linux 系统（x86_64） | smartdns.1.yyyy.MM.dd-REL.x86_64-linux-all.tar.gz | 64 位 Linux 系统 |
| 标准 Linux 系统（x86） | smartdns.1.yyyy.MM.dd-REL.x86-linux-all.tar.gz | 32 位 Linux 系统 |
| WSL | smartdns.1.yyyy.MM.dd-REL.x86_64-linux-all.tar.gz | WSL |
| Optware | smartdns.1.yyyy.MM.dd-REL.mips-optware-all.ipk | MIPS 大端架构的 Optware 系统 |
| Optware（MIPS Little Endian） | smartdns.1.yyyy.MM.dd-REL.mipsel-optware-all.ipk | MIPS 小端架构的 Optware 系统 |
| Optware（ARM） | smartdns.1.yyyy.MM.dd-REL.arm-optware-all.ipk | ARM 小端架构的 Optware 系统 |
| OpenWrt（MIPS） | smartdns.1.yyyy.MM.dd-REL.mips-openwrt-all.ipk | MIPS 大端架构的 OpenWrt 系统 |
| OpenWrt（MIPS Little Endian） | smartdns.1.yyyy.MM.dd-REL.mipsel-openwrt-all.ipk | MIPS 小端架构的 OpenWrt 系统 |
| OpenWrt（ARM） | smartdns.1.yyyy.MM.dd-REL.arm-openwrt-all.ipk | ARM 小端架构的 OpenWrt 系统 |
| OpenWrt LuCI | luci-app-smartdns.1.yyyy.MM.dd-REL.all.ipk | OpenWrt 管理界面 |
| OpenWrt LuCI | luci-app-smartdns.1.yyyy.MM.dd-REL.all-luci-compat-all.ipk | OpenWrt 管理界面、OpenWrt 18.xx 及之前版本 |

**[前往 Release 页面下载](https://github.com/pymumu/smartdns/releases)。**

**请注意：**

* Release 释出的软件包采取静态编译，无外部依赖，但体积大。若需要小体积软件包，请自行编译或从 OpenWrt / Entware 仓库获取。

* 静态编译的软件包未强制判断 CPU 架构，安装不正确的软件包将会导致服务无法启动，请确保正确安装对应的版本。

## 安装和使用

### 标准 Linux 系统 / 树莓派

--------------

1. 安装
   
    下载配套安装包，并上传到 Linux 系统中。 

    标准 Linux 系统（X86 / X86_64）请执行如下命令安装：

    ```shell
    $ tar zxf smartdns.1.yyyy.MM.dd-REL.x86_64-linux-all.tar.gz
    $ cd smartdns
    $ chmod +x ./install
    $ ./install -i
    ```

    树莓派或其他 Debian 系系统（ARM / ARM64）请执行如下命令安装：

    ```shell
    # dpkg -i smartdns.1.yyyy.MM.dd-REL.arm-debian-all.deb
    ```

2. 修改配置
   
    安装完成后，可配置 SmartDNS 的上游服务器信息。

    一般情况下，只需要增加 `server `[`IP`]`:port` 和 `server-tcp `[`IP`]`:port` 配置项。

    请尽可能配置多个上游 DNS 服务器，包括国内外的服务器。

    具体配置参数请参考[配置文件说明](#配置文件说明)。  
   
    ```shell
    # vi /etc/smartdns/smartdns.conf
    ```

    `/etc/smartdns/smartdns.conf`配置包含如下基本内容：
    ```
    # 指定监听的端口号
    bind []:53 
    # 指定上游服务器
    server 1.1.1.1
    server-tls 8.8.8.8
    # 指定域名规则
    address /example.com/1.2.3.4
    domain-rule /example.com/ -address 1.2.3.4
    ```

3. 启动服务
   
    ```shell
    # systemctl enable smartdns
    # systemctl start smartdns
    ```

4. 将 DNS 请求转发到 SmartDNS 解析
   
    修改本地路由器的 DNS 服务器，将 DNS 服务器配置为 SmartDNS。
   
   * 登录到本地网络的路由器中，配置树莓派，分配其静态 IP 地址。
   * 修改 WAN 口或者 DHCP DNS 为树莓派 IP 地址。
     **注意：**
      I. 每款路由器配置方法不尽相同，请在网络上搜索对应配置方法。
      II. 华为等路由器可能不支持配置 DNS 为本地 IP，可修改电脑端或手机端的 DNS 服务器为树莓派 IP。

5. 检测服务是否配置成功
   
    执行
   
   ```shell
   $ nslookup -querytype=ptr smartdns
   ```
   
    查看命令结果中的 `name` 是否为 `smartdns` 或你的主机名，如果是则表示生效
   
   ```shell
   $ nslookup -querytype=ptr smartdns
   Server:         192.168.1.1
   Address:        192.168.1.1#53
   
   Non-authoritative answer:
   smartdns        name = smartdns.
   ```

### OpenWrt

--------------

1. 安装
   
    将软件包（使用 WinSCP 等）上传到路由器的 `/root` 目录，执行如下命令安装
   
   ```shell
   # opkg install smartdns.1.yyyy.MM.dd-REL.xxxx.ipk
   # opkg install luci-app-smartdns.1.yyyy.MM.dd-REL.all.ipk
   ```
   
   * **注意：** 19.07 之前的版本，请务必安装 `luci-app-smartdns.1.yyyy.MM.dd-REL.all-luci-compat-all.ipk`。

2. 修改配置
   
    登录 OpenWrt 管理页面，打开 `Services` -> `SmartDNS` 进行配置。
   
   * 在 `Upstream Servers` 增加上游 DNS 服务器配置，建议配置多个国内外 DNS 服务器。
   * 在 `Domain Address` 指定特定域名的 IP 地址，可用于广告屏蔽。

3. 启用服务
     
  * 替换默认Dndmasq为主DNS。
    
    登录 OpenWrt 管理界面，点击 `Services` -> `SmartDNS` -> `port`，设置端口号为`53`，smartdns会自动接管主DNS服务器。

  * 检测转发服务是否配置成功
    
    执行
    
    ```shell
    $ nslookup -querytype=ptr smartdns
    ```
    
    查看命令结果中的 `name` 是否为 `smartdns` 或你的主机名，如果是则表示生效
    
    ```shell
    $ nslookup -querytype=ptr smartdns
    Server:         192.168.1.1
    Address:        192.168.1.1#53
    
    Non-authoritative answer:
    smartdns        name = smartdns.
       ```

4. 启动服务
   
    勾选配置页面中的 `Enable（启用）`来启动 SmartDNS。

5. **注意：**
   
   * 如已经安装 ChinaDNS，建议将 ChinaDNS 的上游配置为 SmartDNS。
   * 当smartdns的端口为53时，将自动接管dnsmasq为主dns。配置其他端口时，会重新启用dnsmasq为主dns。
   * 若在此过程中发生异常，可使用如下命令还原dnsmasq为主DNS

   ```shell
   uci delete dhcp.@dnsmasq[0].port
   uci commit dhcp
   /etc/init.d/dnsmasq restart
   ```

### 华硕路由器原生固件 / 梅林固件

--------------

**说明：** 梅林固件派生自华硕固件，理论上可以直接使用华硕配套的安装包使用。但目前未经验证，如有问题，请提交 Issue。

1. 准备
   
    在使用此软件时，需要确认路由器是否支持 U 盘，并准备好 U 盘一个。

2. 启用 SSH 登录
   
    登录管理界面，点击 `系统管理` -> `系统设置`，配置 `Enable SSH` 为 `Lan Only`。  
    SSH 登录用户名密码与管理界面相同。

3. 下载 `Download Master`
   
    在管理界面点击 `USB 相关应用` -> `Download Master` 下载。  
    下载完成后，启用 `Download Master`，如果不需要下载功能，此时可以卸载 `Download Master`，但要保证卸载前 `Download Master` 是启用的。  

4. 安装 SmartDNS
   
    将软件包（使用 WinSCP 等）上传到路由器的 `/tmp/mnt/sda1` 目录（或网上邻居复制到 sda1 共享目录），执行如下命令安装
   
   ```shell
   # ipkg install smartdns.1.yyyy.MM.dd-REL.mipsbig.ipk
   ```

5. 重启路由器使服务生效
   
    待路由器启动后， 执行
   
   ```shell
   $ nslookup -querytype=ptr smartdns
   ```
   
    查看命令结果中的 `name` 是否为 `smartdns` 或你的主机名，如果是则表示生效
   
   ```shell
   $ nslookup -querytype=ptr smartdns
   Server:         192.168.1.1
   Address:        192.168.1.1#53
   
   Non-authoritative answer:
   smartdns        name = smartdns.
   ```

6. **额外说明**
   
    上述过程，SmartDNS 将安装到 U 盘根目录，采用 Optware 的模式运行。
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
   
    如要修改配置，可以 SSH 登录路由器，使用 vi 命令修改
   
   ```shell
   # vi /opt/etc/smartdns/smartdns.conf
   ```

    `/opt/etc/smartdns/smartdns.conf`配置包含如下基本内容：
    ```
    # 指定监听的端口号
    bind []:53 
    # 指定上游服务器
    server 1.1.1.1
    server-tls 8.8.8.8
    # 指定域名规则
    address /example.com/1.2.3.4
    domain-rule /example.com/ -address 1.2.3.4
    ```
   
   也可以通过网上邻居修改，网上邻居共享目录 `sda1` 看不到 `asusware.mipsbig` 目录，但可以直接在`文件管理器`中输入 `asusware.mipsbig\etc\init.d` 访问
   
   ```shell
   \\192.168.1.1\sda1\asusware.mipsbig\etc\init.d
   ```

### Optware / Entware

--------------

1. 准备
   
    在使用此软件时，需要确认路由器是否支持 U 盘，并准备好 U 盘一个。

2. 安装 SmartDNS
   
    将软件（使用 WinSCP 等）上传到路由器的 `/tmp` 目录，执行如下命令安装
   
   ```shell
   # ipkg install smartdns.1.yyyy.MM.dd-REL.mipsbig.ipk
   ```

3. 修改 SmartDNS 配置
   
   ```shell
   # vi /opt/etc/smartdns/smartdns.conf
   ```

   `/opt/etc/smartdns/smartdns.conf`配置包含如下基本内容：
    ```
    # 指定监听的端口号
    bind []:53 
    # 指定上游服务器
    server 1.1.1.1
    server-tls 8.8.8.8
    # 指定域名规则
    address /example.com/1.2.3.4
    domain-rule /example.com/ -address 1.2.3.4
    ```
   
    另外，如需支持 IPv6，可设置工作模式为 `2`，将 DNSmasq 的 DNS 服务禁用，设置 SmartDNS 为主用 DNS 服务器。将文件 `/opt/etc/smartdns/smartdns-opt.conf` 中的 `SMARTDNS_WORKMODE` 的值修改为 `2`
   
   ```shell
   SMARTDNS_WORKMODE="2"
   ```

4. 重启路由器使服务生效
   
    待路由器启动后， 执行
   
   ```shell
   $ nslookup -querytype=ptr smartdns
   ```
   
    查看命令结果中的 `name` 是否为 `smartdns` 或你的主机名，如果是则表示生效
   
   ```shell
   $ nslookup -querytype=ptr smartdns
   Server:         192.168.1.1
   Address:        192.168.1.1#53
   
   Non-authoritative answer:
   smartdns        name = smartdns.
   ```
   
    **注意：** 若服务没有自动启动，则需要设置 Optware / Entware 自动启动，具体方法请参考 Optware/Entware 的文档。

### WSL

--------------

1. 安装 WSL
   
    安装 WSL 运行环境，发行版本选择 Ubuntu 系统为例。安装步骤请参考 [WSL 安装说明](https://docs.microsoft.com/zh-CN/windows/wsl/install)

2. 安装 SmartDNS
   
    下载适用于 WSL 的安装包，并解压到如 D 盘根目录。解压后目录如下：
   
   ```shell
   D:\SMARTDNS
   ├─etc
   │  ├─default
   │  ├─init.d
   │  └─smartdns
   ├─package
   │  └─windows
   ├─src
   └─systemd
   ```
   
     双击 `D:\smartdns\package\windows` 目录下的 `install.bat` 进行安装。要求输入密码时，请输入 `WLS ubuntu` 的密码。

3. 修改配置
   
    用记事本等打开 `D:\smartdns\etc\smartdns` 目录中的 `smartdns.conf` 配置文件配置 SmartDNS。
   
    一般情况下，只需要增加 `server [IP]:port` 和 `server-tcp [IP]:port` 配置项，
    尽可能配置多个上游DNS服务器，包括国内外的服务器。
   
    具体配置请参考[配置文件说明](#配置文件说明)。
     `smartdns.conf` 配置包含如下基本内容：
    ```
    # 指定监听的端口号
    bind []:53 
    # 指定上游服务器
    server 1.1.1.1
    server-tls 8.8.8.8
    # 指定域名规则
    address /example.com/1.2.3.4
    domain-rule /example.com/ -address 1.2.3.4
    ```

4. 重新加载配置
   
    双击 `D:\smartdns\package\windows` 目录下的 `reload.bat` 进行重新加载。要求输入密码时，请输入 `WLS ubuntu` 的密码。

5. 将 DNS 请求转发到 SmartDNS 解析
   
    将 Windows 的默认 DNS 服务器修改为 `127.0.0.1`，具体步骤参考 Windows [更改 TCP/IP 设置](https://support.microsoft.com/zh-cn/help/15089/windows-change-tcp-ip-settings)。

6. 检测服务是否配置成功
   
    执行
   
   ```shell
   $ nslookup -querytype=ptr smartdns
   ```
   
    查看命令结果中的 `name` 是否为 `smartdns` 或你的主机名，如果是则表示生效
   
   ```shell
   $ nslookup -querytype=ptr smartdns
   Server:         192.168.1.1
   Address:        192.168.1.1#53
   
   Non-authoritative answer:
   smartdns        name = smartdns.
   ```


## 配置文件说明

配置建议：**smartdns默认已设置为最优模式，适合大部分场景的DNS查询体验改善，一般情况只需要增加上游服务器地址即可，无需做其他配置修改；如有其他配置修改，请务必了解其用途，避免修改后起到反作用。**

| 键名 | 功能说明 | 默认值 | 可用值/要求 | 举例 |
| :--- | :--- | :--- | :--- | :--- |
| server-name | DNS 服务器名称 | 操作系统主机名 / smartdns | 符合主机名规格的字符串 | server-name smartdns |
| bind | DNS 监听端口号  | [::]:53 | 可绑定多个端口。<br>IP:PORT: 服务器 IP:端口号<br>[-group]: 请求时使用的 DNS 服务器组<br>[-no-rule-addr]：跳过 address 规则<br>[-no-rule-nameserver]：跳过 Nameserver 规则<br>[-no-rule-ipset]：跳过 ipset 和 nftset 规则<br>[-no-rule-soa]：跳过 SOA(#) 规则<br>[-no-dualstack-selection]：停用双栈测速<br>[-no-speed-check]：停用测速<br>[-no-cache]：停止缓存 | bind :53 |
| bind-tcp | DNS TCP 监听端口号 | [::]:53 | 可绑定多个端口。<br>IP:PORT: 服务器 IP:端口号<br>[-group]: 请求时使用的 DNS 服务器组<br>[-no-rule-addr]：跳过 address 规则<br>[-no-rule-nameserver]：跳过 nameserver 规则<br>[-no-rule-ipset]：跳过 ipset 和 nftset 规则。<br>[-no-rule-soa]：跳过 SOA(#) 规则<br>[-no-dualstack-selection]：停用双栈测速<br>[-no-speed-check]：停用测速<br>[-no-cache]：停止缓存 | bind-tcp :53 |
| cache-size | 域名结果缓存个数 | 512 | 大于等于 0 的数字 | cache-size 512 |
| cache-persist | 是否持久化缓存 | 自动。<br>当 cache-file 所在的位置有超过 128 MB 的可用空间时启用，否则禁用。 | [yes\|no] | cache-persist yes |
| cache-file | 缓存持久化文件路径 | /tmp/smartdns.cache | 合法路径字符串 | cache-file /tmp/smartdns.cache |
| tcp-idle-time | TCP 链接空闲超时时间 | 120 | 大于等于 0 的数字 | tcp-idle-time 120 |
| rr-ttl | 域名结果 TTL | 远程查询结果 | 大于 0 的数字 | rr-ttl 600 |
| rr-ttl-min | 允许的最小 TTL 值 | 远程查询结果 | 大于 0 的数字 | rr-ttl-min 60 |
| rr-ttl-max | 允许的最大 TTL 值 | 远程查询结果 | 大于 0 的数字 | rr-ttl-max 600 |
| rr-ttl-reply-max | 允许返回给客户端的最大 TTL 值 | 远程查询结果 | 大于 0 的数字 | rr-ttl-reply-max 60 |
| local-ttl | 本地HOST，address的TTL值 | rr-ttl-min | 大于 0 的数字 | local-ttl  60 |
| max-reply-ip-num | 允许返回给客户的最大IP数量 | IP数量 | 大于 0 的数字 | max-reply-ip-num 1 |
| log-level | 设置日志级别 | error | fatal、error、warn、notice、info 或 debug | log-level error |
| log-file | 日志文件路径 | /var/log/smartdns/smartdns.log | 合法路径字符串 | log-file /var/log/smartdns/smartdns.log |
| log-size | 日志大小 | 128K | 数字 + K、M 或 G | log-size 128K |
| log-num | 日志归档个数 | 2 | 大于等于 0 的数字 | log-num 2 |
| audit-enable | 设置审计启用 | no | [yes\|no] | audit-enable yes |
| audit-file | 审计文件路径 | /var/log/smartdns/smartdns-audit.log | 合法路径字符串 | audit-file /var/log/smartdns/smartdns-audit.log |
| audit-size | 审计大小 | 128K | 数字 + K、M 或 G | audit-size 128K |
| audit-num | 审计归档个数 | 2 | 大于等于 0 的数字 | audit-num 2 |
| conf-file | 附加配置文件 | 无 | 合法路径字符串 | conf-file /etc/smartdns/smartdns.more.conf |
| server | 上游 UDP DNS | 无 | 可重复。<br>[ip][:port]：服务器 IP:端口（可选）<br>[-blacklist-ip]：配置 IP 过滤结果。<br>[-whitelist-ip]：指定仅接受参数中配置的 IP 范围<br>[-group [group] ...]：DNS 服务器所属组，比如 office 和 foreign，和 nameserver 配套使用<br>[-exclude-default-group]：将 DNS 服务器从默认组中排除 | server 8.8.8.8:53 -blacklist-ip -group g1 |
| server-tcp | 上游 TCP DNS | 无 | 可重复。<br>[ip][:port]：服务器 IP:端口（可选）<br>[-blacklist-ip]：配置 IP 过滤结果<br>[-whitelist-ip]：指定仅接受参数中配置的 IP 范围。<br>[-group [group] ...]：DNS 服务器所属组，比如 office 和 foreign，和 nameserver 配套使用<br>[-exclude-default-group]：将 DNS 服务器从默认组中排除  | server-tcp 8.8.8.8:53 |
| server-tls | 上游 TLS DNS | 无 | 可重复。<br>[ip][:port]：服务器 IP:端口（可选)<br>[-spki-pin [sha256-pin]]：TLS 合法性校验 SPKI 值，base64 编码的 sha256 SPKI pin 值<br>[-host-name]：TLS SNI 名称, 名称设置为-，表示停用SNI名称<br>[-tls-host-verify]：TLS 证书主机名校验<br> [-no-check-certificate]：跳过证书校验<br>[-blacklist-ip]：配置 IP 过滤结果<br>[-whitelist-ip]：仅接受参数中配置的 IP 范围<br>[-group [group] ...]：DNS 服务器所属组，比如 office 和 foreign，和 nameserver 配套使用<br>[-exclude-default-group]：将 DNS 服务器从默认组中排除 | server-tls 8.8.8.8:853 |
| server-https | 上游 HTTPS DNS | 无 | 可重复。<br>https://[host][:port]/path：服务器 IP:端口（可选）<br>[-spki-pin [sha256-pin]]：TLS 合法性校验 SPKI 值，base64 编码的 sha256 SPKI pin 值<br>[-host-name]：TLS SNI 名称<br>[-http-host]：http 协议头主机名<br>[-tls-host-verify]：TLS 证书主机名校验<br> [-no-check-certificate]：跳过证书校验<br>[-blacklist-ip]：配置 IP 过滤结果<br>[-whitelist-ip]：仅接受参数中配置的 IP 范围。<br>[-group [group] ...]：DNS 服务器所属组，比如 office 和 foreign，和 nameserver 配套使用<br>[-exclude-default-group]：将 DNS 服务器从默认组中排除 | server-https https://cloudflare-dns.com/dns-query |
| speed-check-mode | 测速模式选择 | 无 | [ping\|tcp:[80]\|none] | speed-check-mode ping,tcp:80,tcp:443 |
| response-mode | 首次查询响应模式 | first-ping |模式：[fisrt-ping\|fastest-ip\|fastest-response]<br> [first-ping]: 最快ping响应地址模式，DNS上游最快查询时延+ping时延最短，查询等待与链接体验最佳;<br>[fastest-ip]: 最快IP地址模式，查询到的所有IP地址中ping最短的IP。需等待IP测速; <br>[fastest-response]: 最快响应的DNS结果，DNS查询等待时间最短，返回的IP地址可能不是最快。| response-mode first-ping |
| address | 指定域名 IP 地址 | 无 | address /domain/[ip\|-\|-4\|-6\|#\|#4\|#6] <br>- 表示忽略 <br># 表示返回 SOA <br>4 表示 IPv4 <br>6 表示 IPv6 | address /www.example.com/1.2.3.4 |
| nameserver | 指定域名使用 server 组解析 | 无 | nameserver /domain/[group\|-], group 为组名，- 表示忽略此规则，配套 server 中的 -group 参数使用 | nameserver /www.example.com/office |
| ipset | 域名 ipset | 无 | ipset /domain/[ipset\|-\|#[4\|6]:[ipset\|-][,#[4\|6]:[ipset\|-]]]，-表示忽略 | ipset /www.example.com/#4:dns4,#6:- |
| ipset-timeout | 设置 ipset 超时功能启用  | no | [yes\|no] | ipset-timeout yes |
| nftset | 域名 nftset | 无 | nftset /domain/[#4\|#6\|-]:[family#nftable#nftset\|-][,#[4\|6]:[family#nftable#nftset\|-]]]，-表示忽略；ipv4 地址的 family 只支持 inet 和 ip；ipv6 地址的 family 只支持 inet 和 ip6；由于 nft 限制，两种地址只能分开存放于两个 set 中。| nftset /www.example.com/#4:inet#mytab#dns4,#6:- |
| nftset-timeout | 设置 nftset 超时功能启用  | no | [yes\|no] | nftset-timeout yes |
| nftset-debug | 设置 nftset 调试功能启用  | no | [yes\|no] | nftset-debug yes |
| domain-rules | 设置域名规则 | 无 | domain-rules /domain/ [-rules...]<br>[-c\|-speed-check-mode]：测速模式，参考 speed-check-mode 配置<br>[-a\|-address]：参考 address 配置<br>[-n\|-nameserver]：参考 nameserver 配置<br>[-p\|-ipset]：参考ipset配置<br>[-t\|-nftset]：参考nftset配置<br>[-d\|-dualstack-ip-selection]：参考 dualstack-ip-selection<br> [-no-serve-expired]：禁用过期缓存 | domain-rules /www.example.com/ -speed-check-mode none |
| domain-set | 设置域名集合 | 无 | domain-set [options...]<br>[-n\|-name]：域名集合名称 <br>[-t\|-type]：域名集合类型，当前仅支持list，格式为域名列表，一行一个域名。<br>[-f\|-file]：域名集合文件路径。<br> 选项需要配合address, nameserver, ipset, nftset等需要指定域名的地方使用，使用方式为 /domain-set:[name]/| domain-set -name set -type list -file /path/to/list <br> address /domain-set:set/1.2.4.8 |
| bogus-nxdomain | 假冒 IP 地址过滤 | 无 | [ip/subnet]，可重复 | bogus-nxdomain 1.2.3.4/16 |
| ignore-ip | 忽略 IP 地址 | 无 | [ip/subnet]，可重复 | ignore-ip 1.2.3.4/16 |
| whitelist-ip | 白名单 IP 地址 | 无 | [ip/subnet]，可重复 | whitelist-ip 1.2.3.4/16 |
| blacklist-ip | 黑名单 IP 地址 | 无 | [ip/subnet]，可重复 | blacklist-ip 1.2.3.4/16 |
| force-AAAA-SOA | 强制 AAAA 地址返回 SOA | no | [yes\|no] | force-AAAA-SOA yes |
| force-qtype-SOA | 强制指定 qtype 返回 SOA | qtype id | [<qtypeid> \| ...] | force-qtype-SOA 65 28
| prefetch-domain | 域名预先获取功能 | no | [yes\|no] | prefetch-domain yes |
| dnsmasq-lease-file | 支持读取dnsmasq dhcp文件解析本地主机名功能 | 无 | dnsmasq dhcp lease文件路径 | dnsmasq-lease-file /var/lib/misc/dnsmasq.leases |
| serve-expired | 过期缓存服务功能 | yes | [yes\|no]，开启此功能后，如果有请求时尝试回应 TTL 为 0 的过期记录，并发查询记录，以避免查询等待 |
| serve-expired-ttl | 过期缓存服务最长超时时间 | 0 | 秒，0 表示停用超时，大于 0 表示指定的超时的秒数 | serve-expired-ttl 0 |
| serve-expired-reply-ttl | 回应的过期缓存 TTL | 5 | 秒，0 表示停用超时，大于 0 表示指定的超时的秒数 | serve-expired-reply-ttl 30 |
| dualstack-ip-selection | 双栈 IP 优选 | yes | [yes\|no] | dualstack-ip-selection yes |
| dualstack-ip-selection-threshold | 双栈 IP 优选阈值 | 15ms | 单位为毫秒（ms） | dualstack-ip-selection-threshold [0-1000] |
| user | 进程运行用户 | root | user [username] | user nobody |
| ca-file | 证书文件 | /etc/ssl/certs/ca-certificates.crt | 合法路径字符串 | ca-file /etc/ssl/certs/ca-certificates.crt |
| ca-path | 证书文件路径 | /etc/ssl/certs | 合法路径字符串 | ca-path /etc/ssl/certs |

## 常见问题

1. SmartDNS 和 DNSmasq 有什么区别？
   
    SmartDNS 在设计上并不是 DNSmasq 的替代品，它的主要功能集中在 DNS 解析增强上，增强部分有：
   
   * 多上游服务器并发请求，对结果进行测速后，返回最佳结果；
   * address、ipset 域名匹配采用高效算法，查询匹配更加快速，即使是路由器设备也依然高效；
   * 域名匹配支持忽略特定域名，可单独匹配 IPv4 和 IPv6，支持多样化定制；
   * 针对广告屏蔽功能做增强，返回 SOA，屏蔽广告效果更佳；
   * IPv4、IPv6 双栈 IP 优选机制，在双网情况下，选择最快的网络通讯；
   * 支持最新的 TLS 和 HTTPS 协议，提供安全的 DNS 查询能力；
   * ECS 支持，使查询结果更佳准确；
   * IP 黑名单和忽略 IP 机制，使域名查询更佳准确；
   * 域名预查询，访问常用网站更加快速；
   * 域名 TTL 可指定，使访问更快速；
   * 高速缓存机制，使访问更快速；
   * 异步日志，审计机制，在记录信息的同时不影响 DNS 查询性能；
   * 域名组（group）机制，特定域名使用特定上游服务器组查询，避免隐私泄漏；
   * 第二 DNS 支持自定义更多行为。

2. 如何配置上游服务器最佳？
   
    SmartDNS 有测速机制，在配置上游服务器时，建议配置多个上游 DNS 服务器，包含多个不同区域的服务器，但总数建议在 10 个左右。推荐搭配
   
   * 运营商 DNS。
   * 国内公共 DNS，如 `119.29.29.29`, `223.5.5.5`。
   * 国外公共 DNS，如 `8.8.8.8`, `8.8.4.4`。

3. 如何启用审计日志？
   
    审计日志记录客户端请求的域名，记录信息包括，请求时间，请求 IP，请求域名，请求类型，如果要启用审计日志，在配置界面配置 `audit-enable yes` 启用，`audit-size`、 `audit-file`、`audit-num` 分别配置审计日志文件大小，审计日志文件路径，和审计日志文件个数。审计日志文件将会压缩存储以节省空间。

4. 如何避免隐私泄漏？
   
    默认情况下，SmartDNS 会将请求发送到所有配置的DNS服务器，若上游 DNS 服务器使用DNS，或记录日志，将会导致隐私泄漏。为避免隐私泄漏，请尽量：  
   
   * 配置使用可信的DNS服务器。
   * 优先使用 TLS 查询。
   * 设置上游 DNS 服务器组。

5. 如何屏蔽广告？
   
    SmartDNS 具备高性能域名匹配算法，通过域名方式过滤广告非常高效，如要屏蔽广告，只需要配置类似如下记录即可，如，屏蔽 `*.ad.com`，则配置：
   
   ```sh
   address /ad.com/#
   ```
   
    域名的使后缀模式，过滤 `*.ad.com`，`#` 表示返回 SOA，使屏蔽广告更加高效，如果要单独屏蔽 IPv4 或 IPv6， 在 `#` 后面增加数字，如 `#4` 表示对 IPv4 生效。若想忽略特定子域名的屏蔽，如忽略 `pass.ad.com`，可配置如下：
   
   ```sh
   address /pass.ad.com/-
   ```

6. 如何使用 DNS 查询分流？
   
    某些情况下，需要将有些域名使用特定的 DNS 服务器来查询来做到 DNS 分流。比如
   
   ```sh
   .home -> 192.168.1.1 # .home 结尾的域名发送到 192.168.1.1 解析
   .office -> 10.0.0.1  # .office 结尾的域名发送到 10.0.0.1 解析
   ```
   
    其他域名采用默认的模式解析。
    这种情况的分流配置如下：
   
   ```sh
   # 配置上游，用 -group 指定组名，用 -exclude-default-group 将服务器从默认组中排除。
   server 192.168.1.1 -group home -exclude-default-group
   server 10.0.0.1 -group office -exclude-default-group
   server 8.8.8.8
   
   # 配置解析的域名
   nameserver /.home/home
   nameserver /.office/office
   ```
   
    通过上述配置即可实现 DNS 解析分流，如果需要实现按请求端端口分流，可以配置第二 DNS 服务器，`bind` 配置增加 `--group` 参数指定分流名称。
   
   ```sh
   bind :7053 -group office
   bind :8053 -group home
   ```

7. IPv4、IPv6 双栈 IP 优选功能如何使用？
   
    目前 IPv6 已经开始普及，但 IPv6 网络在速度上，某些情况下还不如 IPv4。为在双栈网络下获得较好的体验，SmartDNS 提供来双栈IP优选机制，同一个域名，若 IPv4 的速度远快与 IPv6，那么 SmartDNS 就会阻止IPv6的解析、使用 IPv4 访问。可在配置文件中通过设置 `dualstack-ip-selection yes` 启用此功能，通过 `dualstack-ip-selection-threshold [time]` 来修改阈值。如果要完全禁止 IPv6 AAAA记录解析，可设置 `force-AAAA-SOA yes`。

8. 如何提高缓存效率，加快访问速度？
   
    SmartDNS 提供了域名缓存机制，对查询的域名，进行缓存，缓存时间符合 DNS TTL 规范。为提高缓存命中率，可采用如下措施：  
   
   * 适当增大缓存的记录数
     
     通过 `cache-size` 来设置缓存记录数。  
     
     查询压力大的环境下，并且有内存大的机器的情况下，可适当调大。  
   
   * 适当设置最小 TTL 值
     
     通过 `rr-ttl-min` 将最低 DNS TTL 时间设置为一个合理值，延长缓存时间。
     
     建议是超时时间设置在 10～30 分钟，避免服务器域名变化时，查询到失效域名。
   
   * 开启域名预获取功能
     
     通过 `prefetch-domain yes` 来启用域名预先获取功能，提高查询命中率。
     
     配合上述 TTL 超时时间，SmartDNS 将在域名 TTL 即将超时时，再次发送查询请求，并缓存查询结果供后续使用。频繁访问的域名将会持续缓存。此功能将在空闲时消耗更多的 CPU。
   
   * 过期缓存服务功能  
     
     通过 `serve-expired` 来启用过期缓存服务功能，可提高缓存命中率的同时，降低CPU占用。
     
     此功能会在TTL超时后，将返回 TTL=0 给客户端，并且同时再次发送查询请求，并缓存新的结果给后续使用。

9. 第二 DNS 如何自定义更多行为？
   
   第二 DNS 可以作为其他 DNS 服务器的上游，提供更多的查询行为，通过 bind 配置支持可以绑定多个端口，不同端口可设置不同的标志，实现不同的功能，如
   
   ```sh
   # 绑定 6053 端口，6053 端口的请求将采用配置 office 组的上游查询，且不对结果进行测速，忽略 address 的配置地址
   bind [::]:6053 -no-speed-check -group office -no-rule-addr
   ```

10. DoT 的 SPKI 如何获取？
    SPKI 可以通过 DNS 服务商发布的页面获取，如果没有发布，可以通过如下命令获取，其中将对应IP地址更换为要获取 SPKI 的 IP 地址。

    ```sh
    $ echo | openssl s_client -connect '1.0.0.1:853' 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
    ```

11. iOS系统解析缓慢问题怎么解决？  
    IOS14开始，苹果支持了DNS HTTPS(TYPE65)记录的解析，此功能用于快速DNS查询和解决HTTPS链接相关的问题，但当前还是草案，另外会导致广告屏蔽等功能失效，建议通过如下配置关闭TYPE65记录查询。

    ```sh
    force-qtype-SOA 65
    ```

12. 如何解析本地主机名称？  
    smartdns可以配合DNSMASQ的dhcp lease文件支持本地主机名->IP地址的解析，可以配置smartdns读取dnsmasq的lease文件，并支持解析。具体配置参数如下，（注意，DNSMASQ lease文件每个系统可能不一样，需要按实际情况配置）

    ```
    dnsmasq-lease-file /var/lib/misc/dnsmasq.leases
    ```

    配置完成后，可以直接使用主机名连接对应的机器。但需要注意：

    * Windows系统默认使用mDNS解析地址，如需要在windows下用使用smartdns解析，则需要在主机名后面增加`.`，表示使用DNS解析。如`ping smartdns.`

13. 域名集合如何使用？  
    为方便按集合配置域名，对于有/domain/的配置，可以指定域名集合，方便维护。具体方法为：
    
    * 使用`domain-set`配置集合文件，如
    
    ```sh
    domain-set -name ad -file /etc/smartdns/ad-list.conf
    ```

    ad-list.conf的格式为一个域名一行，如
    
    ```
    ad.com
    site.com
    ```

    * 在有/domain/配置的选项使用域名集合，只需要将`/domain/`配置为`/domain-set:[集合名称]/`即可，如：

    ```sh
    address /domain-set:ad/#
    domain-rules /domain-set:ad/ -a #
    nameserver /domain-set:ad/server
    ...
    ```

14. 更多问题  
    如有更多问题，请查阅或提交issue: [https://github.com/pymumu/smartdns/issues](https://github.com/pymumu/smartdns/issues)

## 编译

  SmartDNS 提供了编译软件包的脚本（`package/build-pkg.sh`），支持编译 LuCI、Debian、OpenWrt 和 Optware 安装包。

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
