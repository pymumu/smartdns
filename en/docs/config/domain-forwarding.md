---
hide:
  - toc
---

# DNS Forwarding

SmartDNS can support DNS Forwarding by using specific DNS servers to query specific domain names, such as:

```shell
.local -> 192.168.1.1 # .local domain names are sent to 192.168.1.1 for resolution
.com -> 10.0.0.1  # .com domain names are sent to 10.0.0.1 for resolution
```

Other domain names are resolved using the default mode. The configuration of this forwarding is as follows:

## Configuration Steps

1. Configure the upstream server group and group the upstream server using `-group`

    ```shell
    # Configure upstream server, specify group name with -group, and exclude the server from the default group with -exclude-default-group.
    server 192.168.1.1 -group local -exclude-default-group
    server 10.0.0.1 -group com -exclude-default-group
    server 8.8.8.8
    ```

1. Configure the server group used for corresponding domain name resolution

    ```shell
    # Upstream server rules, .local domain names use servers in the local group for all queries
    nameserver /local/local
    # Upstream server rules, .com domain names use servers in the com group for all queries
    nameserver /com/com
    ```

Similarly, local can be replaced with domestic, and com can be replaced with overseas.

## More Abilities

By configuring the above, DNS resolution forward can be realized. If you need to forward according to the requesting port, you can configure the second DNS server, and add the `--group` parameter to the `bind` configuration to specify the forward name.

```shell
bind :7053 -group public
bind :8053 -group local
```

By configuring the above, requests to the 7053 port are all queried using the public group, and requests to the 8053 port are all queried using the local group.
