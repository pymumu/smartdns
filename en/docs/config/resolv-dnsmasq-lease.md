---
hide:
  - toc
---

# Parsing Local Hostnames

## Using DNSMASQ Lease File

SmartDNS can support the resolution of local hostname->IP address by cooperating with DNSMASQ dhcp lease file. SmartDNS can be configured to read the lease file of dnsmasq and support resolution. The specific configuration parameters are as follows 
(Note that DNSMASQ lease files may vary from system to system and need to be configured according to actual conditions)

```shell
dnsmasq-lease-file /var/lib/misc/dnsmasq.leases
```

After the configuration is completed, you can directly connect to the corresponding machine using the hostname. However, it should be noted that:

1. The Windows system defaults to using mDNS to resolve addresses. If you need to use smartdns for resolution under Windows, you need to add `.` after the hostname to indicate the use of DNS resolution, such as `ping smartdns.`
1. SmartDNS will monitor file changes periodically and automatically load mapping relationships that have changed.
1. If your local network DHCP is configured with a DNS suffix, you can use the `local-domain` parameter to set the local domain name.

## Using mDNS Lookup

SmartDNS can use mDNS to query local hostnames or IP addresses. The specific configuration is as follows:

```shell
mdns-lookup yes
```
