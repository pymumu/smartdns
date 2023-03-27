---
hide:
  - toc
---

# ASUS router native firmware / Merlin firmware

Note: Merlin firmware is derived from ASUS firmware and can theoretically be used directly with the ASUS package. However, it is currently unverified. If you have any questions, please submit an issue.

## Prepare

When using this software, you need to confirm whether the router supports U disk and prepare a USB disk.

## Enable SSH login

Log in to the management interface, click `System Management`-> Click `System Settings` and configure `Enable SSH` to `Lan Only`.  
The SSH login username and password are the same as the management interface.

## Install `Download Master`

In the management interface, click `USB related application`-> click `Download Master` to download.  
After the download is complete, enable `Download Master`. If you do not need the download function, you can uninstall `Download Master` here, but make sure that Download Master is enabled before uninstalling.  

## Install SmartDNS

Upload the software to the router's `/tmp/mnt/sda1` directory using winscp. (or copy the network neighborhood to the sda1 shared directory)

```shell
ipkg install smartdns.xxxxxxx.mipsbig.ipk
```

## Restart router

After the router is started, use `nslookup -querytype=ptr smartdns` to query the domain name.  
See if the `name` item in the command result is displayed as `smartdns` or `hostname`, such as `smartdns`

```shell
pi@raspberrypi:~/code/smartdns_build $ nslookup -querytype=ptr smartdns
Server:         192.168.1.1
Address:        192.168.1.1#53

Non-authoritative answer:
smartdns         name = smartdns.
```

## Note

In the above process, smartdns will be installed to the root directory of the U disk and run in optware mode.  
Its directory structure is as follows: (only smartdns related files are listed here)

```shell
USB DISK
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

To modify the configuration, you can use ssh to login to the router and use the vi command to modify it.

```shell
vi /opt/etc/smartdns/smartdns.conf
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
domain-rules /example.com/ -address 1.2.3.4
```

It can also be modified from Network Neighborhood. From the neighbor sharing directory `sda1` you can't see the `asusware.mipsbig` directory, but you can directly enter `asusware.mipsbig\etc\init.d` in `File Manager` to modify it.

```shell
\\192.168.1.1\sda1\asusware.mipsbig\etc\init.d
```
