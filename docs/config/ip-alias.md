---
hide:
  - toc
---

# IP别名

smartdns提供了IP地址别名映射功能，可以将查询结果中的IP或IP段映射为特定IP地址；  
此特性可用用于具有anycast IP的CDN网络加速。比如Cloudflare的CDN加速。

## IP别名映射

映射指定的IP地址到目标地址，如将1.2.3.4的C类地址全部映射到192.168.1.1

```
ip-alias 1.2.3.4/24 192.168.1.1
```

## 设置特定域名忽略IP别名

某些情况下，需要设置特定域名的结果不进行IP别名转换，则可通过域名规则忽略IP别名。

```
domain-rules /example.com/ -no-ip-alias
```


## Cloudflare CDN加速

Cloudflare CDN的IP地址都是anycast IP地址，用户可通过任意Cloudflare的IP地址来访问其托管的网站。  
通过此特性，我们可以找到自己网络访问Cloudflare CDN最快的IP地址，并设置IP别名，来加速所有托管在Cloudflare上的网站。

其步骤如下：

### 获取Cloudflare的IP地址范围并保持为IP列表文件

Cloudflare公开了其CDN的IP地址范围，具体范围在这里可以找到https://www.cloudflare.com/ips/

IPV4：https://www.cloudflare.com/ips-v4/#  
IPV6：https://www.cloudflare.com/ips-v6/#  

将上述列表保存为文本，比如：`cloudflare-ipv4.txt`, `cloudflare-ipv6.txt`

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

### 查找本网络访问Cloudflare最快的IP

社区提供了找到最快Cloudflare IP地址的工具：[CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest)，我们可以使用此工具找到最快的IP地址。

对应命令如下

```
./CloudflareSpeedTest -url https://down.heleguo.top/download/100MB.zip
```

执行成功后，将会获得最快的IP地址。  
由于工具随机使用了一些IP地址测速，可以多执行几次上述命令，以确保获取到最快IP地址。

### 配置smartdns加速

原理是通过ip-alias命令将Cloudflare的整个anycast IP映射到CloudflareSpeedTest获取到的最快的IP地址上。  
配置smartdns如下

```
# 设置Cloudflare IPV4别名映射
ip-set -name cloudflare-ipv4 -file /path/to/cloudflare-ipv4.txt
ip-rules ip-set:cloudflare-ipv4 -ip-alias 162.159.58.17,162.159.58.124

# 设置Cloudflare IPV6别名映射
ip-set -name cloudflare-ipv6 -file /path/to/cloudflare-ipv6.txt
ip-rules ip-set:cloudflare-ipv6 -ip-alias 2606:4700:17:d8e7:5e98:7d62:6674:c5a7
```
