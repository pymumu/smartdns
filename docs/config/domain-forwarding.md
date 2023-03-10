---
hide:
  - toc
---

# DNS分流

smartdns可以支持将特定域名使用特定的 DNS 服务器来查询来做到 DNS 分流。比如

```shell
.home -> 192.168.1.1 # .home 结尾的域名发送到 192.168.1.1 解析
.office -> 10.0.0.1  # .office 结尾的域名发送到 10.0.0.1 解析
```

其他域名采用默认的模式解析，这种情况的分流配置如下：

## 配置步骤

1. 配置上游服务器组，并对上游使用`-group`进行分组

    ```shell
    # 配置上游，用 -group 指定组名，用 -exclude-default-group 将服务器从默认组中排除。
    server 192.168.1.1 -group home -exclude-default-group
    server 10.0.0.1 -group office -exclude-default-group
    server 8.8.8.8
    ```

1. 配置对应域名解析时使用的服务器组

    ```shell
    # 上游服务器规则，.home结尾的域名全部使用home组的服务器查询
    nameserver /home/home
    # 上游服务器规则，.office结尾的域名全部使用office组查询。
    nameserver /office/office
    ```

类似的，home可以换成domestic，office可以换成oversea

## 更多能力

通过上述配置即可实现 DNS 解析分流后，如果需要实现按请求端端口分流，可以配置第二 DNS 服务器，`bind` 配置增加 `--group` 参数指定分流名称。

```shell
bind :7053 -group office
bind :8053 -group home
```

通过上述配置，到7053端口查询的请求，全部使用office查询，到8053端口查询的请求，全部使用home查询。
