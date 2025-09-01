---
hide:
  - toc
---

# SmartDNS仪表盘

SmartDNS提供了插件化的仪表盘功能，可通过单独安装仪表盘插件，实现提供SmartDNS仪表盘功能。

![SmartDNS-WebUI](../assets/smartdns-webui.png)

## 启用SmartDNS仪表盘

1. 通过`plugin`插件参数配置，例子如下：

    ```shell
    # 启用仪表盘
    plugin smartdns_ui.so
    # 设置服务端口号。
    smartdns-ui.ip http://[::]:6080
    ```

    注意：

    * 默认用户名密码为：**`admin/password`**。  
    * 仪表盘采用插件机制，若smartdns程序为静态编译的版本，则不支持仪表盘插件。


1. 可通过`data-dir`参数设置数据文件存储路径：

    ```shell
    data-dir /var/lib/smartdns
    ```

1. 启用HTTPS服务：

    `smartdns-ui.ip`参数，使用`https://`的前缀来启用HTTPS服务。

    ```
    # 启用HTTPS服务
    smartdns-ui.ip https://[::]:6080
    
    # 指定证书文件
    bind-cert-file /path/to/ca-file
    bind-cert-key-file /path/to/ca-key-file
    ```

    注意：

    * 启用HTTPS服务时，若未指定证书文件，smartdns将自动生成`CN`为`SmartDNS Root`的根证书文件和相关的证书链。
    * 可以将`SmartDNS Root`根证书加入到信任域中来启用安全访问。

1. 设置查询日志保留的最长时间：

    通过`smartdns-ui.max-query-log-age`来设置查询日志保存的最长时间。

    ```shell
    # 设置最长查询日志保留时间，单位为秒
    smartdns-ui.max-query-log-age 86400
    ```

更多配置项参考[`配置选项`](../configuration.md)页面。
