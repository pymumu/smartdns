---
hide:
  - toc
---

# EDNS Client Subnet

SmartDNS provides the ability to configure edns-client-subnet for speed testing and proxy queries. In the following scenarios, you can configure edns-client-subnet to optimize network query results:

## IP optimization across carriers

Carrier DNS servers typically provide the IP addresses of their own network or CDN servers to clients. For example, when querying example.com using the local carrier DNS, the result is the IP address of the local carrier network, Carriers typically do not provide IP addresses across carriers unless a website is only available on a specific carrier network. However, some websites may require IP addresses that cross multiple provinces, resulting in significant delay compared to accessing the same website across carriers within the same province. In this case, you can use the edns-client-subnet feature to query an IP address across an external network, and then configure SmartDNS to return a smaller, more efficient IP address to the client.

### Configuration

Assume your broadband is provided by China Unicom, You want query IP from China Telecom and test speed, You can configure edns-client-subnet as follows:

```shell
server 8.8.8.8 -subnet [China Telecom IP]  
```

This will return the IP address of the China Telecom IP network to the client, and SmartDNS will return the IP address to the client based on the speed testing results. You can also configure the -subnet parameter to be an IPv4 or IPv6 address to configure the client subnet.

## Through the proxy query

When SmartDNS queries the proxy, the corresponding query results are optimized based on the proxy server's IP. If you want to optimize the results of the proxy query and the local carrier, you can configure edns-client-subnet to optimize the results.

### Configuration

Assume China Telecom users query DNS through a Beijing proxy. You can configure edns-client-subnet as follows:

```shell
server 8.8.8.8 -proxy beijing -subnet [China Telecom IP]  
```

This will query the IP address of the China Telecom network through the Beijing proxy, but since the client subnet is configured as the China Telecom IP, the IP address returned by 8.8.8.8 will be the IP address of the China Telecom network.
