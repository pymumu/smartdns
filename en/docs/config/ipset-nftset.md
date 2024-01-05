---
hide:
  - toc
---

# Use ipset and nftset

Like Dnsmasq, smartdns supports ipset and nftset, which can use TPROXY to transparently forward specific domain names. The comparison of transparent forwarding tools is as follows:

1. Tools: iptable, nftable

    iptable: A mature routing rule configuration tool.  
    nftable: A more powerful rule configuration tool that is becoming mainstream.

## ipset configuration

1. Basic configuration

    The following parameters can be used to configure NFTSet rules for specified domain names.

    ```shell
    # set global ipset
    ipset ipsetname
    # set ipset for specified domain names
    ipset /domain/ipset
    ipset /domain/[#4:ipsetv4,#6:ipsetv6]
    # ignore ipset rule for specified domain names
    ipset /domain/-
    ```

1. Timeout

    SmartDNS sets IPSet to support enabling timeout function, which can avoid too many IP addresses in NFTSet and reduce gateway performance.

    ```shell
    ipset-timeout yes
    ```

1. Automatically add to IPSet after speed measurement fails

    SmartDNS can add IP addresses that fail the speed measurement to IPSet, and then forward them through related IP rules.

    ```shell
    ipset-no-speed ipsetname
    ```

## nftset configuration

1. Basic configuration

    The following parameters can be used to configure IPSet rules for specified domain names.

    ```shell
    # set global nftset
    nftset [#4:ip#table#set,#6:ipv6#table#setv6]
    # set nftset for specified domain names
    nftset /domain/[#4:ip#table#set,#6:ipv6#table#setv6]
    # ignore ipset rule for specified domain names
    nftset /domain/#4:-,#6:-
    ```

1. Timeout

    SmartDNS sets IPSet to support enabling timeout function, which can avoid too many IP addresses in IPSet and reduce gateway performance.

    ```shell
    nftset-timeout yes
    ```

1. Automatically add to IPSet after speed measurement fails

    SmartDNS can add IP addresses that fail the speed measurement to IPSet, and then forward them through related IP rules.

    ```shell
    nftset-no-speed ipsetname
    ```

1. Debugging

    If debugging is needed, nftset's debugging function can be enabled.

    ```shell
    nftset-debug yes
    ```

## Set ipset and nftset for specific service ports

The bind parameter of smartdns supports setting ipset and nftset. When the port with ipset and nftset set receives a request, it will set ipset and nftset for the query request of this port.

Through the following configuration, all query requests for ports can be set into ipset, for example, all query results of the second DNS can be put into ipset.

```shell
bind [::]:6053 -ipset [ipset] -nftset [nftset]
```

* -ipset: Refer to ipset options for parameter options.
* -nftset: options refer to nftset.

Note: when bind is configured with ipset or nftset, `domain-prefretch`, `serve-expired`, and `dualstack-selection` functions will be automatically disabled.
