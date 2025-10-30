---
hide:
  - toc
---

# OpenWrt

## Installation

Upload the software to the /root directory of the router with winscp or other tool, and execute the following command to install it.

after openwrt 24.10
```shell
apk add --allow-untrusted smartdns.1.yyyy.MM.dd-REL.xxxx.ipk
apk add --allow-untrusted luci-app-smartdns-lite.1.yyyy.MM.dd-REL.all.ipk
```

before openwrt 24.10 
```shell
opkg install smartdns.1.yyyy.MM.dd-REL.xxxx.ipk
opkg install luci-app-smartdns-lite.1.yyyy.MM.dd-REL.all.ipk
```

- Note: For versions before OpenWrt 19.07, please install `luci-app-smartdns.xxxxxxxxx.all-luci-compat-all` package.

## Configuration

Log in to the OpenWrt management page and open `Services`->`SmartDNS` to configure SmartDNS.

- Add upstream DNS server configuration to `Upstream Servers`. It is recommended to configure multiple DNS servers at home and abroad.
- Specify the IP address of a specific domain name in `Domain Address`, which can be used for ad blocking.

## Start Service

There are two ways to use the SmartDNS service, `one is directly as the primary DNS service`, `the other is as the upstream of dnsmasq`.  
By default, SmartDNS uses the first method. You can choose according to your needs in the following two ways.

## Method 1: SmartDNS as primary DNS Server

- **Enable SmartDNS as primary DNS Server**

    Log in to the router, click on `Services`->`SmartDNS`->`port`, input port `53`, smartdns will run as primary DNS Server.

- **Check if the service is configured successfully**

    Query domain name with `nslookup -querytype=ptr smartdns`
    See if the `name` item in the command result is displayed as `smartdns` or `hostname`, such as `smartdns`

    ```shell
    pi@raspberrypi:~/code/smartdns_build $ nslookup -querytype=ptr smartdns
    Server:         192.168.1.1
    Address:        192.168.1.1#53

    Non-authoritative answer:
    smartdns         name = smartdns.
    ```

## Note

- When the port of smartdns is 53, it will automatically take over dnsmasq as the primary dns. When configuring other ports, dnsmasq is re-enabled as primary dns.
- If an exception occurs during this process, you can use the following command to restore dnsmasq as the primary DNS

```shell
uci delete dhcp.@dnsmasq[0].port
uci commit dhcp
/etc/init.d/dnsmasq restart
```
