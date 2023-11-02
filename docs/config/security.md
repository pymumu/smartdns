---
hide:
  - toc
---

# 安全相关

smartdns为DNS服务器，默认绑定53端口，这时smartdns需要root权限，并且有可能导致外网也能进行数据查询。所以通过如下方式对smartdns进行安全加固

## 使用非root权限运行

通过user指定非root用户运行，如使用nobody运行

```shell
user nobody
```

## 绑定特定的IP或网口

通过bind参数，指定绑定的IP地址，或网口

1. 绑定特定的IP

    ```shell
    bind 192.168.1.1:53
    ```

1. 绑定特定的网口

    ```shell
    bind [::]:53@eth0
    ```

## 对公网提供查询时，使用TLS服务器

使用TLS服务器对外提供服务

```shell
bind-tls [::]:853@eth0
```

## 启用审计日志

smartdns可以通过如下配置，启用审计日志，记录DNS查询请求

```
audit-enable yes
audit-num 16
audit-size 16M
audit-file /var/log/smartdns/smartdns-audit.log
```