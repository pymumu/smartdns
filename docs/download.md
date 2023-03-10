---
hide:
  - navigation
  - toc
---

# 下载

SmartDNS目前已经合入到主流系统的软件仓库，可以直接使用软件包管理命令安装。但如果主流系统不支持或更新不及时可是单独手工下载安装。

## 使用官方安装源

smartdns已经合入主流系统的软件仓库，可以直接使用系统安装命令直接安装。

系统|安装方式|说明|
--|--|--
openwrt|opkg update<br />opkg install luci-app-smartdns<br />opkg install smartdns|22.03之后的系统。<br />软件源路径：<https://downloads.openwrt.org/releases/>
ddwrt|官方最新固件service页面->SmartDNS Resolver->启用。|选择界面参考：<https://forum.dd-wrt.com/demo/Services.html>
debian|apt-get install smartdns|
entware|ipkg update<br />ipkg install smartdns|软件源路径：<https://bin.entware.net/>

## 手工下载安装

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
| Windows | smartdns-rs https://github.com/mokeyish/smartdns-rs | Rust版本SmartDNS | [Rust版本SmartDNS](https://github.com/mokeyish/smartdns-rs) |
| MacOS | smartdns-rs https://github.com/mokeyish/smartdns-rs | Rust版本SmartDNS |

**[前往 Release 页面下载](https://github.com/pymumu/smartdns/releases)。**  

**请注意：**

- Release 释出的软件包采取静态编译，无外部依赖，但体积大。若需要小体积软件包，请自行编译或从 OpenWrt / Entware 仓库获取。

- 静态编译的软件包未强制判断 CPU 架构，安装不正确的软件包将会导致服务无法启动，请确保正确安装对应的版本。