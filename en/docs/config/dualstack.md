---
hide:
  - toc
---

# Dual Stack Selection

Most home users have already had IPV6, IPV4 dual-stack network. Currently, most operating systems will use IPV6 network first. However, in some cases, IPV4 network may be better than IPV6, and in other cases, IPV6 network may be better than IPV4.

SmartDNS provides a dual-stack Selection function, which will automatically perform speed measurement and prioritize the IP address with faster speed for the client operating system to use.

## Configuration Steps

1. Use `dualstack-ip-selection` to enable dual-stack Selection.

    ```shell
    dualstack-ip-selection yes
    ```

1. If IPV6 is preferred, you can adjust the threshold using `dualstack-ip-selection-threshold`.

    ```shell
    dualstack-ip-selection-threshold 10
    ```

    Note:

    1. The unit is ms. The IP address with speed greater than the specified value will be preferred.

1. Allow pure IPV6 addresses.

    By default, smartdns always returns IPV4 addresses, because some software does not have the ability to access IPV6. However, if you do need to use a pure IPV6 address, you can allow smartdns to prefer only IPV6.

    ```shell
    dualstack-ip-allow-force-AAAA yes
    ```

## Special Applications

In some cases, it may be necessary to temporarily disable dual-stack Selection of certain domain names, which can be achieved in the following two ways:

1. Disable Selection of queried domain names on specified ports.

    ```shell
    bind [::]:53 -no-dualstack-selection
    ```

1. Disable Selection of specific domain names.

    ```shell
    domain-rules /example.com/ -dualstack-ip-selection no
    ```
