---
hide:
  - toc
---

# 缓存

SmartDNS提供了缓存能力，开启缓存的情况下，能提供更好的DNS查询请求；smartdns提供的过期缓存功能会将体验更进一步提升。

## 缓存配置

SmartDNS可以通过`cache-size`配置缓存的条数，同时也可以通过`cache-persist`来配置是否持久化缓存，也可以通过`cache-file`来指定缓存文件存储路径

```shell
cache-size 32768
cache-persist yes
cache-file /path/to/cache/file
```

注意：

  1. smartdns默认自动根据磁盘空间是否启用缓存。
  1. 缓存文件只有在进程正常退出的时候才会保存供下次使用。

## 缓存预获取

Smartdns可以设置缓存预获取，避免缓存超时，配置预先获取后，smartdns将在域名超时前的5s内，重新进行域名查询。并对域名的热度进行排序。

```shell
prefetch-domain yes
```

注意：

  1. 此功能将会导致smaratdns消耗更多的CPU。

## 过期缓存

过期缓存，也要乐观缓存，其功能指定是，当DNS域名的TTL到0时，其结果仍然存储在缓存中，等下次查询时，仍然将缓存的结果返回给客户端，避免客户端等待。乐观缓存的前提时，DNS的对应的IP地址不会频繁变化。

具体乐观缓存的原理可以参考(RFC 8767) (https://www.rfc-editor.org/rfc/rfc8767)

smartdns过期缓存处理流程

```mermaid

%%{init: {'theme':'forest'}}%%
sequenceDiagram
    participant client as 客户端
    participant smartdns as SmartDNS
    participant Server as 上游DNS服务器
    client->>smartdns: DNS查询
    smartdns->>smartdns: 域名在缓存中，且已经过期。
    smartdns->>client: 返回结果过期的域名结果，TTL为3
    smartdns->>+Server: 上游查询DNS
    Server->>-smartdns: 返回查询结果
    smartdns->>smartdns: 测速，并缓存结果
    client->>smartdns: 3s后客户端再次查询，获取最佳结果。

```

通过上述序列图可以看到，当缓存过期时，smartdns仍然将过期的IP地址发给客户端，这样客户端就能很快的进行连接服务器，这种机制的前提是服务器IP地址没有变化。

现实中，大部分情况下，修改域名IP地址后，是不会立即生效到千家万户的，因为一般IP变化域名后，全球域名系统刷新完成最长可能要72小时。  
即时出现过期缓存中的IP地址，故障失效，smartdns返回给客户端过期IP的TTL只有3s，那么3s后，客户端就会重新使用新的IP，表现在客户端程序中，可能就是要刷新页面重试一次。  
并且，针对实现场景，smartdns可以设置预获取来尽量避免此问题发生。

所以，主要场景下开启过期缓存是比较好的实践。

## 配置步骤

1. 开启过期缓存

    ```shell
    serve-expired yes
    ```

1. 配置过期缓存超时时间

    此时间表示过期缓存多长时间未访问，则从缓存中释放。

    ```shell
    serve-expired-ttl 259200
    ```

1. 配置过期缓存响应TTL

    此时间表示当缓存中域名TTL超时时，返回给客户端的TTL时间，让客户端在下列TTL时间后再次查询。

    ```shell
    serve-expired-reply-ttl 3
    ```

1. 过期缓存预获取时间

    此时间表示，过期缓存在多长时间未访问，主动进行预先获取，以避免IP无效；开启过期缓存后，prefetch的功能将和未开启不同。

    ```shell
    prefetch-domain yes
    serve-expired-prefetch-time 21600
    ```
