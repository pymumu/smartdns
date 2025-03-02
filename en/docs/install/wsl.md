---
hide:
  - toc
---


# Windows 10 WSL Installation/WSL ubuntu

## Install Windows 10 WSL ubuntu

Install the Windows 10 WSL environment and select Ubuntu as default distribution, Please refer to [WSL installation instructions](https://docs.microsoft.com/en-us/windows/wsl/install-win10) for installation steps

## Install smartdns

download install package `smartdns.xxxxxxxx.x86_64-linux-all.tar.gz`, and unzip to the `D:\` directory, after decompression, the directory is as follows:

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

Double-click `install.bat` in the `D:\smartdns\package\windows` directory for installation. Please enter the password for `WSL ubuntu` when input password.

## Configuration

Edit `smartdns.conf` configuration file in `D:\smartdns\etc\smartdns` directory, you can configure the upstream server to  smartdns. Refer to the `Configuration Parameters` for specific configuration parameters.  
In general, you only need to add `server [IP]:port`, `server-tcp [IP]:port` configuration items.  
Configure as many upstream DNS servers as possible, including servers at home and abroad. Please refer to the `Configuration Parameters` section for configuration parameters.  

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

## Start Service

Double-click `reload.bat` in the `D:\smartdns\package\windows` directory for reload.

## Forwarding DNS request to SmartDNS

Modify the default DNS server for Windows to `127.0.0.1`, with these steps referred to [IP configuration](https://support.microsoft.com/en-us/help/15089/windows-change-tcp-ip-settings)

## Check if the service is configured successfully

Query domain name with `nslookup -querytype=ptr smartdns`  
Check if the `name` item in the command result is displayed as `smartdns` or `hostname`, such as `smartdns`

```shell
pi@raspberrypi:~/code/smartdns_build $ nslookup -querytype=ptr smartdns
Server:         192.168.1.1
Address:        192.168.1.1#53

Non-authoritative answer:
smartdns         name = smartdns.
```