---
hide:
  - toc
---

# Bootstrap DNS

对于域名类的上游服务器，SmartDNS会使用其他IP地址类的服务器进行解析，所以一般情况下无需配置BootStrap DNS，但如果有特殊需求，需要指定BootStrap DNS，则可以通过如下方式配置：

1. 方法一：对所有服务器指定bootstrap DNS  

    使用`-bootstrap-dns`参数，指定特定的server为bootstrap DNS。  

    ```shell
    server 1.2.3.4 -bootstrap-dns
    server dns.server
    ```

1. 方法二：针对特定服务器  

    使用`nameserver /domain/bootstrap-dns`参数指定特定域名使用指定DNS解析。

    ```shell
    # 配置bootstrap DNS
    server 1.2.3.4 -group bootstrap-dns
    nameserver /dns.server/bootstrap-dns
    # 此服务器将使用1.2.3.4解析
    server dns.server
    ```

