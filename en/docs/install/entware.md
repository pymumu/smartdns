---
hide:
  - toc
---

# EntWare

## Prepare

When using this software, you need to confirm whether the router supports USB disk and prepare a USB disk.

## Install SmartDNS

Upload the software to `/tmp` directory of the router using winscp, and run the following command to install.

```shell
ipkg install smartdns.xxxxxxx.mipsbig.ipk
```

## Modify the smartdns configuration

```shell
Vi /opt/etc/smartdns/smartdns.conf
```

`smartdns.conf` example:

```shell
# set listen port
bind []:53 
# set upstream servers
server 1.1.1.1
server-tls 8.8.8.8
# set domain rules
address /example.com/1.2.3.4
domain-rule /example.com/ -address 1.2.3.4
```

Note: if you need to support IPV6, you can set the work-mode to `2`, this will disable the DNS service of dnsmasq, and smartdns run as the primary DNS server. Change `SMARTDNS_WORKMODE` in the file `/opt/etc/smartdns/smartdns-opt.conf` to `2`.

```shell
SMARTDNS_WORKMODE="2"
```

## Restart the router to take effect

After the router is started, use `nslookup -querytype=ptr smartdns` to query the domain name.
See if the `name` item in the command result is displayed as `smartdns` or `hostname`, such as `smartdns`

```shell
Pi@raspberrypi:~/code/smartdns_build $ nslookup -querytype=ptr smartdns
Server: 192.168.1.1
Address: 192.168.1.1#53

Non-authoritative answer:
smartdns        name = smartdns.
```

Note: If the service does not start automatically, you need to set optware/entware to start automatically. For details, see the optware/entware documentation.
