---
hide:
  - navigation
  - toc
---

# Download

## Use official installation source

smartdns can already be installed using system package management tools.

System|Installation|Instructions|
--|--|--
openwrt|opkg update<br />opkg install luci-app-smartdns<br />opkg install smartdns|systems after 22.03. <br />Software source: <https://downloads.openwrt.org/releases/>
ddwrt|latest firmware. goto services page abd enable SmartDNS Resolver. |Demo: <https://forum.dd-wrt.com/demo/Services.html>
debian|apt-get install smartdns|
entware|ipkg update<br />ipkg install smartdns|Software source: <https://bin.entware.net/>

## Download From Release Page

--------------

Download the matching version of the SmartDNS installation package. The corresponding installation package is as follows.

|system |package|Description
|-----|-----|-----
|Standard Linux system (Raspberry Pi)| smartdns.xxxxxxxx.arm-debian-all.deb|Support Raspberry Pi Raspbian stretch, Debian 9 system.
|Standard Linux system (Armbian arm64)| smartdns.xxxxxxxx.aarch64-debian-all.deb|Support Armbian debian stretch, Debian 9 system.
|Standard Linux system (x86_64)| smartdns.xxxxxxxx.x86_64-linux-all.tar.gz|Support for x86_64 Linux systems.
|Windows 10 WSL (ubuntu)| smartdns.xxxxxxxx.x86_64-linux-all.tar.gz|Windows 10 WSL ubuntu.
|Standard Linux system (x86)| smartdns.xxxxxxxx.x86-linux-all.tar.gz|Support for x86_64 systems.
|optware|smartdns.xxxxxxxx.mips-optware-all.ipk|Support the MIPS big-endian architecture for optware。
|optware|smartdns.xxxxxxxx.mipsel-optware-all.ipk|Support the MIPS little-endian architecture for optware。
|optware|smartdns.xxxxxxxx.arm-optware-all.ipk|Support the arm architecture for optware。
|openwrt|smartdns.xxxxxxxx.mips-openwrt-all.ipk|Support the MIPS big-endian architecture for openwrt。
|openwrt|smartdns.xxxxxxxx.mipsel-openwrt-all.ipk|Support the MIPS little-endian architecture for openwrt。
|openwrt|smartdns.xxxxxxxx.arm-openwrt-all.ipk|Support the arm architecture for openwrt。
|openwrt LUCI|luci-app-smartdns.xxxxxxxxx.all.ipk|Openwrt management interface.
|openwrt LUCI|luci-app-smartdns.xxxxxxxxx.all-luci-compat-all|Compat Openwrt management interface for early openwrt.
|Windows|smartdns-rs [https://github.com/mokeyish/smartdns-rs](https://github.com/mokeyish/smartdns-rs)| Rust Version SmartDNS |
|MacOS|smartdns-rs [https://github.com/mokeyish/smartdns-rs](https://github.com/mokeyish/smartdns-rs)| Rust Version SmartDNS |

- The released packages are statically compiled. If you need a small size package, please compile it yourself or obtain it from the openwrt / entware repository.

- **Please download from the Release page: [Download here](https://github.com/pymumu/smartdns/releases)**

```shell
https://github.com/pymumu/smartdns/releases
```

- For the installation procedure, please refer to the following sections.
