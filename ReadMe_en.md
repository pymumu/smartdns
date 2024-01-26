# SmartDNS

![SmartDNS](doc/smartdns-banner.png)  
SmartDNS is a local DNS server. SmartDNS accepts DNS query requests from local clients, obtains DNS query results from multiple upstream DNS servers, and returns the fastest access results to clients. supports secure DNS protocols like DoT (DNS over TLS), DoH (DNS over HTTPS), better protect privacy,  
Avoiding DNS pollution and improving network access speed, supports high-performance ad filtering.

Unlike dnsmasq's all-servers, smartdns returns the fastest access resolution.

Support Raspberry Pi, openwrt, ASUS router, Windows and other devices.  

## Usage

Please visit website: [https://pymumu.github.io/smartdns](https://pymumu.github.io/smartdns/en)

## Software Show

**Ali DNS**  
Use Ali DNS to query Baidu's IP and test the results.  

```shell
pi@raspberrypi:~/code/smartdns_build $ nslookup www.baidu.com 223.5.5.5
Server:         223.5.5.5
Address:        223.5.5.5#53

Non-authoritative answer:
www.baidu.com   canonical name = www.a.shifen.com.
Name:   www.a.shifen.com
Address: 180.97.33.108
Name:   www.a.shifen.com
Address: 180.97.33.107

pi@raspberrypi:~/code/smartdns_build $ ping 180.97.33.107 -c 2
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

**smartdns**  
Use SmartDNS to query Baidu IP and test the results.

```shell
pi@raspberrypi:~/code/smartdns_build $ nslookup www.baidu.com
Server:         192.168.1.1
Address:        192.168.1.1#53

Non-authoritative answer:
www.baidu.com   canonical name = www.a.shifen.com.
Name:   www.a.shifen.com
Address: 14.215.177.39

pi@raspberrypi:~/code/smartdns_build $ ping 14.215.177.39 -c 2
PING 14.215.177.39 (14.215.177.39) 56(84) bytes of data.
64 bytes from 14.215.177.39: icmp_seq=1 ttl=56 time=6.31 ms
64 bytes from 14.215.177.39: icmp_seq=2 ttl=56 time=5.95 ms

--- 14.215.177.39 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 5.954/6.133/6.313/0.195 ms

```

From the comparison, smartdns found the fastest IP address to visit www.baidu.com, so accessing Baidu's DNS is 5 times faster than Ali DNS.

## Features

1. **Multiple Virtual DNS server**  
   Support multiple virtual DNS servers with different ports, rules, and clients.

1. **Multiple upstream DNS servers**  
   Support configuring multiple upstream DNS servers and query at the same time.the query will not be affected, Even if there is a DNS server exception.  

1. **Support per-client query control**  
   Support controlling clients using different query rules based on MAC and IP addresses, enabling features such as parental control.  

1. **Return the fastest IP address**  
   Support finding the fastest access IP address from the IP address list of the domain name and returning it to the client to avoid DNS pollution and improve network access speed.

1. **Support for multiple query protocols**  
   Support UDP, TCP, DOT(DNS over TLS), DOH(DNS over HTTPS) queries and service, and non-53 port queries, effectively avoiding DNS pollution and protect privacy, and support query DNS over socks5, http proxy.

1. **Domain IP address specification**  
   Support configuring IP address of specific domain to achieve the effect of advertising filtering, and avoid malicious websites.

1. **Domain name high performance rule filtering**  
   Support domain name suffix matching mode, simplify filtering configuration, filter 200,000 recording and take time <1ms.

1. **Linux/Windows multi-platform support**  
   Support standard Linux system (Raspberry Pi), openwrt system various firmware, ASUS router native firmware. Support Windows 10 WSL (Windows Subsystem for Linux).

1. **Support IPV4, IPV6 dual stack**  
   Support IPV4, IPV6 network, support query A, AAAA record, dual-stack IP selection, and filter IPV6 AAAA record.

1. **DNS64**  
   Support DNS64 translation.

1. **High performance, low resource consumption**  
   Multi-threaded asynchronous IO mode, cache cache query results.

1. **DNS domain forwarding**  
   Support DNS forwarding, ipset and nftables. Support setting the domain result to ipset and nftset set when speed check fails.

## Architecture

![Architecture](doc/architecture.png)

1. SmartDNS receives DNS query requests from local network devices, such as PCs and mobile phone query requests.
1. SmartDNS sends query requests to multiple upstream DNS servers, using standard UDP queries, non-standard port UDP queries, and TCP queries.
1. The upstream DNS server returns a list of Server IP addresses corresponding to the domain name. SmartDNS detects the fastest Server IP with local network access.
1. Return the fastest accessed Server IP to the local client.

## Compile

smartdns contains scripts for compiling packages, supports compiling luci, debian, openwrt, optware installation packages, and can execute `package/build-pkg.sh` compilation.

## [Donate](#donate)  

If you feel that this project is helpful to you, please donate to us so that the project can continue to develop and be more perfect.

### PayPal

[![Support via PayPal](https://cdn.rawgit.com/twolfson/paypal-github-button/1.0.0/dist/button.svg)](https://paypal.me/PengNick/)

### Alipay

![alipay](doc/alipay_donate.jpg)

### Wechat
  
![wechat](doc/wechat_donate.jpg)

## Open Source License

Smartdns is licensed to the public under the GPL V3 License.
