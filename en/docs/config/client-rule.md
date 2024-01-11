---
hide:
  - toc
---

# Client Rules

smartdns supports setting different rules for clients based on their IP addresses or MAC addresses, allowing for:

  * Parental control: Restricting access to specific websites for certain clients.
  * Access control: Prohibiting unauthorized clients from making queries.
  * Client-based domain-based query routing: Binding rule groups with upstream groups, so that different clients can query different upstream servers.

## Parental Control

  By configuring smartdns to use specific upstream queries for certain clients, you can implement parental control by restricting access to specific domains or IP addresses.

  ```
  # Enable Rule Group
  group-begin child
  # Set client IP for the rule group
  client-rules 192.168.1.13
  # Set client MAC address for the rule group
  client-rules 01:02:03:04:05:06
  # Set upstream server for the rule group
  server 1.2.3.4 -e
  # Block specific domain
  address /block.com/#
  # Block specific IP
  ignore-ip 2.2.2.2
  group-end
  ```

For convenience in management, multiple configuration files can also be used, such as:

  1. Main configuration file

    ```
    conf-file child.conf -group child
    ```

  1. Included Configuration File

    ```
    # Set client IP for the rule group
    client-rules 192.168.1.13
    # Set upstream server for the rule group
    server 1.2.3.4 -e
    # Block specific domain
    address /block.com/#
    # Block specific IP
    ignore-ip 2.2.2.2
    ```

The configuration blocks of group-begin and group-end are equivalent to the configuration files included with conf-file -group.

## Access Control

  smartdns supports basic ACL functionality, which allows you to enable and set the hosts that are allowed to access.

  ```
  # Enable ACL
  acl-enable yes
  # Set allowed hosts
  client-rules 192.168.1.2/24
  ```

## Client-based Domain-based Query Forwarding

Similar to parental control, smartdns can route specific hosts that require redirection and are accessed with ipset/nftset.

  1. Main Configuration File

    ```
    conf-file oversea.conf -group oversea
    ```

  1. Included Configuration File

    ```
    # Set the client IP for the rule group
    client-rules 192.168.1.13
    # Set the upstream servers for the rule group
    server-https https://1.2.3.4 -e
    server-tls tls://1.2.3.4 -e
    # Disable speed check
    speed-check-mode none
    # Disable IPV6 and HTTPS logging
    force-qtype-SOA 28 65
    # Set ipset
    ipset group-tv
    ```