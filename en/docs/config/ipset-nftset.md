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

    The following parameters can be used to configure IPSet rules for specified domain names.

    ```shell
    nftset /domain/[#4:ip#table#set,#6:ipv6#table#setv6]
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

## nftset configuration

1. Basic configuration

    The following parameters can be used to configure NFTSet rules for specified domain names.

    ```shell
    ipset /domain/ipset
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
