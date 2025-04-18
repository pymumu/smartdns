---
hide:
  - navigation
  - toc
---

# SmartDNS

![SmartDNS](assets/smartdns-banner.png)  

SmartDNS is a local DNS server with dashboard. SmartDNS accepts DNS query requests from local clients, obtains DNS query results from multiple upstream DNS servers, and returns the fastest access results to clients. supports secure DNS protocols like DoT (DNS over TLS), DoH (DNS over HTTPS), better protect privacy, Avoiding DNS pollution and improving network access speed, supports high-performance ad filtering.

Unlike dnsmasq's all-servers, smartdns returns the fastest ip.

Support Raspberry Pi, openwrt, ASUS router, Windows and other devices.  

## Dashbaord

![SmartDNS-WebUI](assets/smartdns-webui.png)

## Features

1. **Multiple Virtual DNS server**  
   Support multiple virtual DNS servers with different ports, rules, and clients.

1. **Multiple upstream DNS servers**  
   Support configuring multiple upstream DNS servers and query at the same time.the query will not be affected, Even if there is a DNS server exception.  

1. **Support per-client query control**  
   Support controlling clients using different query rules based on MAC and IP addresses, enabling features such as parental control.  

1. **Return the fastest IP address**  
   Supports finding the fastest access IP address from the IP address list of the domain name and returning it to the client to avoid DNS pollution and improve network access speed.

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

![Architecture](assets/architecture.png)

1. SmartDNS receives DNS query requests from local network devices, such as PCs and mobile phone query requests.
1. SmartDNS sends query requests to multiple upstream DNS servers, using standard UDP queries, non-standard port UDP queries, and TCP queries.
1. The upstream DNS server returns a list of Server IP addresses corresponding to the domain name. SmartDNS detects the fastest Server IP with local network access.
1. Return the fastest accessed Server IP to the local client.
