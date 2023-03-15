---
hide:
  - toc
---

# 服务端配置

smartdns目前提供了UDP, TCP, DOT三种服务端模式。

## UDP服务端

1. 通过`bind`参数配置，配置例子如下：

    ```shell
    bind 0.0.0.0:53@eth0
    bind [::]:53@eth0
    bind :53@eth0
    ```

    选项中:

    * @eth0，表示仅在对应的网口上提供服务。
    * [::]:53， 表示监听IPV6和IPV4地址。
    * :53，表示监听IPV4地址

## TCP服务端

1. 通过`bind-tcp`参数配置，配置例子如下：

    ```shell
    bind-tcp 0.0.0.0:53@eth0
    bind-tcp [::]:53@eth0
    bind-tcp :53@eth0
    ```

1. 可选，参数tcp-idle-time控制TCP空闲断链时间

    ```shell
    tcp-idle-time 120
    ```

## DOT服务端

1. 通过`bind-tcp`参数配置，配置例子如下：

    ```shell
    bind-tcp 0.0.0.0:53@eth0
    bind-tcp [::]:53@eth0
    bind-tcp :53@eth0

    ```

1. 设置证书和密钥文件

    ```shell
    bind-cert-file smartdns-cert.pem
    bind-cert-key-file smartdns-key.pem
    bind-cert-key-pass pass
    ```

    选项中:

    * bind-cert-file: 表示证书文件路径。
    * bind-cert-key-file：表示证书密钥文件路径。
    * bind-cert-key-pass： 表示证书密钥文件密码，可选。

    注意：

    上述三个参数如果不指定的情况下，smartdns将会自动在/etc/smartdns目录自动生成自签名证书`smartdns-cert.pem`和`smartdns-key.pem` key文件，CN为smartdns。

1. 可选，参数tcp-idle-time控制TCP空闲断链时间

    ```shell
    tcp-idle-time 120
    ```
