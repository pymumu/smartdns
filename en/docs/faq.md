---
hide:
  - navigation
---

# FAQ

## What is the difference between SmartDNS and DNSMASQ?  

Smartdns is not designed to replace DNSMASQ. The main function of Smartdns is focused on DNS resolution enhancement, the differences are:

- Multiple upstream server concurrent requests, after the results are measured, return the best results;
- `address`, `ipset` domain name matching uses efficient algorithms, query matching is faster and more efficient, and router devices are still efficient.
- Domain name matching supports ignoring specific domain names, and can be individually matched to IPv4, IPV6, and supports diversified customization.
- Enhance the ad blocking feature, return SOA record, this block ads better;
- IPV4, IPV6 dual stack IP optimization mechanism, in the case of dual network, choose the fastest network.
- Supports the latest TLS, HTTPS protocol and provides secure DNS query capabilities.
- DNS anti-poison mechanism, and a variety of mechanisms to avoid DNS pollution.
- ECS support, the query results are better and more accurate.
- IP blacklist support, ignoring the blacklist IP to make domain name queries better and more accurate.
- Domain name pre-fetch, more faster to access popular websites.
- Domain name TTL can be specified to make access faster.
- Cache mechanism to make access faster.
- Asynchronous log, audit log mechanism, does not affect DNS query performance while recording information.
- Domain group mechanism, specific domain names use specific upstream server group queries to avoid privacy leakage.
- The second DNS supports customizing more behavior.

## What is the best practices for upstream server configuration?  

Smartdns has a speed measurement mechanism. When configuring an upstream server, it is recommended to configure multiple upstream DNS servers, including servers in different regions, but the total number is recommended to be around 10. Recommended configuration

- Carrier DNS.
- Public DNS, such as `8.8.8.8`, `8.8.4.4`, `1.1.1.1`.

For specific domain names, if there is a pollution, you can enable the anti-pollution mechanism.

## How to enable the audit log  

The audit log records the domain name requested by the client. The record information includes the request time, the request IP address, the request domain name, and the request type. If you want to enable the audit log, configure `audit-enable yes` in the configuration file, `audit-size`, `Audit-file`, `audit-num` configure the audit log file size, the audit log file path, and the number of audit log files. The audit log file will be compressed to save space.

## How to avoid DNS privacy leaks  

By default, smartdns will send requests to all configured DNS servers. If the upstream DNS servers record DNS logs, it will result in a DNS privacy leak. To avoid privacy leaks, try the following steps:

- Use trusted DNS servers.
- Use TLS servers.
- Set up an upstream DNS server group.

## How to block ads  

Smartdns has a high-performance domain name matching algorithm. It is very efficient to filter advertisements by domain name. To block ads, you only need to configure records like the following configure. For example, if you block `*.ad.com`, configure as follows:

```shell
Address /ad.com/#
```

The suffix mode of the domain name, filtering *.ad.com, `#` means returning SOA record. If you want to only block IPV4 or IPV6 separately, add a number after `#`, such as `#4` is for IPV4 blocking. If you want to ignore some specific subdomains, you can configure it as follows. e.g., if you ignore `pass.ad.com`, you can configure it as follows:

```shell
Address /pass.ad.com/-
```

## DNS query diversion  

In some cases, some domain names need to be queried using a specific DNS server to do DNS diversion. such as.

```shell
.home -> 192.168.1.1
.office -> 10.0.0.1
```

The domain name ending in .home is sent to 192.168.1.1 for resolving
The domain name ending in .office is sent to 10.0.0.1 for resolving
Other domain names are resolved using the default mode.
The diversion configuration for this case is as follows:

```shell
# Upstream configuration, use -group to specify the group name, and -exclude-default-group to exclude the server from the default group.
Server 192.168.1.1 -group home -exclude-default-group
Server 10.0.0.1 -group office -exclude-default-group
Server 8.8.8.8

#Configure the resolved domain name with specific group
Nameserver /.home/home
Nameserver /.office/office
```

You can use the above configuration to implement DNS resolution and offload. If you need to implement traffic distribution on the requesting port, you can configure the second DNS server. The bind configuration is added. The group parameter specifies the traffic distribution name.

```shell
Bind :7053 -group office
Bind :8053 -group home
```

## How to use the IPV4, IPV6 dual stack IP optimization feature  

At present, IPV6 network is not as fast as IPV4 in some cases. In order to get a better experience in the dual-stack network, SmartDNS provides a dual-stack IP optimization mechanism, the same domain name, and the speed of IPV4. Far faster than IPV6, then SmartDNS will block the resolution of IPV6, let the PC use IPV4, the feature is enabled by `dualstack-ip-selection yes`, `dualstack-ip-selection-threshold [time]` is for threshold. if you want to disable IPV6 AAAA record complete, please try `force-AAAA-SOA yes`.

## How to improve cache performance  

Smartdns provides a domain name caching mechanism to cache the queried domain name, and the caching time is in accordance with the DNS TTL specification. To increase the cache hit rate, the following configuration can be taken:

- Increase the number of cache records appropriately  

Set the number of cache records by `cache-size`.
In the case of a query with a high pressure environment and a machine with a large memory, it can be appropriately adjusted.

- Set the minimum TTL value as appropriate  
Set the minimum DNS TTL time to a appropriate value by `rr-ttl-min` to extend the cache time.
It is recommended that the timeout period be set to 10 to 30 minutes to avoid then invalid domain names when domain ip changes.

- Enable domain pre-acquisition  
Enable pre-fetching of domain names with `prefetch-domain yes` to improve query hit rate.
by default, Smartdns will send domain query request again before cache expire, and cache the result for the next query. Frequently accessed domain names will continue to be cached. This feature will consume more CPU when idle.

- Cache serve expired feature  
Enable cache serve expired feature with `serve-expired yes` to improve the cache hit rate and reduce the CPU consumption.
This feature will return TTL = 0 to the client after the TTL timeout, and send a new query request again at the same time, and cache the new results for later query.

## How does the second DNS customize more behavior?  

The second DNS can be used as the upstream of other DNS servers to provide more query behaviors. Bind configuration support can bind multiple ports. Different ports can be set with different flags to implement different functions, such as

```shell
# Binding 6053 port, request for port 6053 will be configured with the upstream query of the office group, and the result will not be measured. The address configuration address is ignored.
bind [::]:6053 -no-speed-check -group office -no-rule-addr
```

## How to get SPKI of DOT  

The SPKI can be obtained from the page published by the DNS service provider. If it is not published, it can be obtained by the following command, replace IP with your own IP.

```shell
echo | openssl s_client -connect '1.0.0.1:853' 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

## How to solve the problem of slow DNS resolution in iOS system?

Since iOS14, Apple has supported the resolution of DNS HTTPS (TYPE65) records. This function is used for solving problems related to HTTPS connections, but it is still a draft, and it will cause some functions such as adblocking fail. It is recommended to disable it through the following configuration.

```shell
force-qtype-SOA 65
```

## How to resolve localhost ip by hostname?  

smartdns can cooperate with the dhcp server of DNSMASQ to support the resolution of local host name to IP address. You can configure smartdns to read the lease file of dnsmasq and support the resolution. The specific configuration parameters are as follows, (note that the DNSMASQ lease file may be different for each system and needs to be configured according to the actual situation)

```shell
dnsmasq-lease-file /var/lib/misc/dnsmasq.leases
```

After the configuration is complete, you can directly use the host name to connect to the local machine. But need to pay attention:

- Windows system uses mDNS to resolve addresses by default. If you need to use smartdns to resolve addresses under Windows, you need to add `.` after the host name, indicating that DNS resolution is used. Such as `ping smartdns.`

## How to use the domain set?  

To facilitate configuring domain names by set, for configurations with /domain/, you can specify a domain name set for easy maintenance. The specific method is:

- Use `domain-set` configuration domain set file:

````shell
domain-set -name ad -file /etc/smartdns/ad-list.conf
````

The format of ad-list.conf is one domain per line:

```shell
ad.com
site.com
```

- To use the domain set, you only need to configure `/domain/` to `/domain-set:[collection name]/`, such as:

````shell
address /domain-set:ad/#
domain-rules /domain-set:ad/ -a #
nameserver /domain-set:ad/server
...
````

## How to use ipset and nftset?  

Similar to Dnsmasq, smartdns supports ipset and nftset, and can transparently forward specific domain names through TPROXY. The comparison of transparent forwarding and tool modes is as follows:

1. Tools: iptable, nftable

    iptable: a mature routing rule configuration tool.
    nftable: A more powerful rule configuration tool that is becoming mainstream.

1. Mode: TPROXY, REDIRECT

    TPROXY: supports UDP and TCP forwarding, and the configuration is a little complicated.
    REDIRECT: only supports TCP, easy to configure.

Here we only take the configuration of the most commonly used iptable/REDIRECT with ipset as an example. The specific forwarding configuration is as follows:

- Set the list of domain names that need to be transparently forwarded in smartdns.conf, for example, `example.com` needs to be transparently forwarded. Then use the ipset option and set the ipset rule of `example.com` to `proxy`.

```shell
# set rules
# -ipset proxy: The matching domain name is set to ipset:proxy.
# -c none: Disable speed check.
# -address #6: Filter IPV6 record.
domain-rules /example.com/ -ipset proxy -c none -address #6
```

- Execute shell commands, set iptable rules, and transparently forward matching domain name requests. The rules are as follows:

```shell
# create ipset
ipset create proxy hash:net
# Set forwarding rules to forward matching requests to port 1081 of this machine
iptables -t nat -I PREROUTING -p tcp -m set --match-set proxy dst -j REDIRECT --to-ports 1081
```

- Open the forwarding program of REDIRECT mode on port 1081 of this machine.

## Bootstrap DNS  

For upstream servers with domain name, smartdns will use servers with IP address types for resolution, so there is no need to configure bootstrap DNS, but if there are special needs, you can specify bootstrap DNS . The steps are as follows:

1. nameserver server upstream server  

    use nameserver set upstream server for domain name  

    ```shell
    server dns.server # this domain name will be resolved by 1.2.3.4
    server 1.2.3.4 -group bootstrap-dns
    nameserver /dns.server/bootstrap-dns
    ```

1. Set bootstrap DNS server  

    use `-bootstrap-dns` option to set server as bootstrap DNS.

    ```shell
    server 1.2.3.4 -bootstrap-dns
    server dns.server
    ```

## More questions

More questions, please read issue: [https://github.com/pymumu/smartdns/issues](https://github.com/pymumu/smartdns/issues)
