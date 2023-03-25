---
hide:
  - toc
---

# DNS Forwarding

SmartDNS can support DNS Forwarding by using specific DNS servers to query specific domain names, such as:

```shell
.home -> 192.168.1.1 # .home domain names are sent to 192.168.1.1 for resolution
.office -> 10.0.0.1  # .office domain names are sent to 10.0.0.1 for resolution
```

Other domain names are resolved using the default mode. The configuration of this forwarding is as follows:

## Configuration Steps

1. Configure the upstream server group and group the upstream server using `-group`

    ```shell
    # Configure upstream server, specify group name with -group, and exclude the server from the default group with -exclude-default-group.
    server 192.168.1.1 -group home -exclude-default-group
    server 10.0.0.1 -group office -exclude-default-group
    server 8.8.8.8
    ```

1. Configure the server group used for corresponding domain name resolution

    ```shell
    # Upstream server rules, .home domain names use servers in the home group for all queries
    nameserver /home/home
    # Upstream server rules, .office domain names use servers in the office group for all queries
    nameserver /office/office
    ```

Similarly, home can be replaced with domestic, and office can be replaced with overseas.

## More Abilities

By configuring the above, DNS resolution forward can be realized. If you need to forward according to the requesting port, you can configure the second DNS server, and add the `--group` parameter to the `bind` configuration to specify the forward name.

```shell
bind :7053 -group office
bind :8053 -group home
```

By configuring the above, requests to the 7053 port are all queried using the office group, and requests to the 8053 port are all queried using the home group.
