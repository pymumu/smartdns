---
hide:
  - toc
---

# Standard Linux system installation/Raspberry Pi, X86_64 system

## Installation

Download the installation package like `smartdns.xxxxxxxx.arm-debian-all.deb` and upload it to the Linux system. Run the following command to install

```shell
dpkg -i smartdns.xxxxxxxx.arm-debian-all.deb
```

For X86-64 system, download the installation package like `smartdns.xxxxxxxx.x86_64-linux-all.tar.gz` and upload it to the Linux system. Run the following command to install

```shell
tar zxf smartdns.xxxxxxxx.x86_64-linux-all.tar.gz
cd smartdns
chmod +x ./install
./install -i
```

**For Ubuntu system:**

- `systemd-resolved` occupies TCP53 and UDP53 ports. You need to manually resolve the port occupancy problem or modify the SmartDNS listening port

- Log files in `/var/log/smartdns/smartdns.log`

## Configuration

After the installation is complete, you can configure the upstream server to  smartdns. Refer to the `Configuration Parameters` for specific configuration parameters.  
In general, you only need to add `server [IP]:port`, `server-tcp [IP]:port` configuration items.  
Configure as many upstream DNS servers as possible, including servers at home and abroad. Please refer to the `Configuration Parameters` section for configuration parameters.  

```shell
vi /etc/smartdns/smartdns.conf
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

## Start Service

```shell
systemctl enable smartdns
systemctl start smartdns
```

## Forwarding DNS request to SmartDNS

Modify the DNS server of the local router and configure the DNS server as SmartDNS.

- Log in to the router on the local network and configure the Raspberry Pi to assign a static IP address.
- Modify the WAN port or DHCP DNS to the Raspberry Pi IP address.

Note:
I. Each router configuration method is different. Please search Baidu for related configuration methods.
II. some routers may not support configuring custom DNS server. in this case, please modify the PC's, mobile phone's DNS server to the ip of Raspberry Pi.

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
