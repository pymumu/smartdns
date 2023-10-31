---
hide:
  - toc
---

# IP Alias

SmartDNS provides IP address alias mapping, which can map the IP or IP range in the query result to a specific IP address.  
This feature can be used for CDN network acceleration with anycast IP, such as Cloudflare's CDN acceleration.

## IP Alias Mapping

Map the specified IP address to the target address, such as mapping the C class address of 1.2.3.4 to 192.168.1.1.

```
ip-alias 1.2.3.4/24 192.168.1.1
```

## Ignore IP Alias for Specific Domains

In some cases, it may be necessary to exclude specific domains from IP alias mapping. This can be achieved by using domain rules to ignore IP alias mapping for those domains.

```
domain-rules /example.com/ -no-ip-alias
```


## Cloudflare CDN Acceleration

Cloudflare CDN's IP addresses are all anycast IP addresses, and users can access websites hosted on Cloudflare through any Cloudflare IP address.  
With this feature, we can find the fastest IP address for accessing Cloudflare CDN on our own network and set up IP aliases to speed up all websites hosted on Cloudflare.

Here are the steps:

### Get the IP address range of Cloudflare and save it as an IP list file

Cloudflare has publicly disclosed the IP address range of its CDN, which can be found here: https://www.cloudflare.com/ips/

IPv4: https://www.cloudflare.com/ips-v4/#  
IPv6: https://www.cloudflare.com/ips-v6/#  

Save the above list as a text file, such as: `cloudflare-ipv4.txt`, `cloudflare-ipv6.txt`

* cloudflare-ipv4.txt
```
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
```

* cloudflare-ipv6.txt
```
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32
```

### Find the Fastest IP Address to Access Cloudflare on Your Network

The community provides a tool to find the fastest Cloudflare IP address: [CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest). We can use this tool to find the fastest IP address.

The corresponding command is as follows:

```
./CloudflareSpeedTest -url https://down.heleguo.top/download/100MB.zip
```

After successful execution, you will get the fastest IP address.  
Since the tool randomly uses some IP addresses for testing, you can execute the above command multiple times to ensure that you get the fastest IP address.

### Configure SmartDNS acceleration

The principle is to use the ip-alias command to map the entire anycast IP of Cloudflare to the fastest IP address obtained from CloudflareSpeedTest.  
Configure SmartDNS as follows:

```
# Set up Cloudflare IPV4 alias mapping
ip-set -name cloudflare-ipv4 -file /path/to/cloudflare-ipv4.txt
ip-rules ip-set:cloudflare-ipv4 -ip-alias 162.159.58.17,162.159.58.124

# Set up Cloudflare IPV6 alias mapping
ip-set -name cloudflare-ipv6 -file /path/to/cloudflare-ipv6.txt
ip-rules ip-set:cloudflare-ipv6 -ip-alias 2606:4700:17:d8e7:5e98:7d62:6674:c5a7
```
