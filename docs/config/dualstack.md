---
hide:
  - toc
---

# 双栈优选

目前大部分家庭用户已经有IPV6，IPV4双栈网络，目前大部分操作系统都会优先使用IPV6网络，但某些域名会出现IPV4网络好于IPV6的情况，另外一些域名会出现IPV6网络好于IPV4的情况。

SmartDNS提供了双栈优选的功能，会自动进行测速，优先让客户端操作系统使用速度快的IP地址。

## 配置步骤

1. 使用`dualstack-ip-selection`配置启用双栈优选

    ```shell
    dualstack-ip-selection yes
    ```

1. 如需要倾向使用IPV6，则可以使用`dualstack-ip-selection-threshold`进行阈值调整

    ```shell
    dualstack-ip-selection-threshold 10
    ```

    注意：

    1. 单位为ms，两个IP地址的速度阈值大于配置值时，才会进行优选。

1. 允许纯IPV6地址。

    smartdns默认情况下总是会返回IPV4地址，原因是某些软件不具备IPV6的访问能力，但如果确实需要使用纯IPV6地址，可以设置允许smartdns仅优选IPV6。

    ```shell
    dualstack-ip-allow-force-AAAA yes
    ```

## 特殊应用

某些情况下，可能要临时关闭某些域名的双栈优选，可以通过如下两种方式：

1. 对指定端口查询的域名关闭优选

    ```shell
    bind [::]:53 -no-dualstack-selection
    ```

1. 对特定域名关闭优选

    ```shell
    domain-rules /example.com/ -dualstack-ip-selection no
    ```
