---
hide:
  - toc
---

# 后备DNS

设置后备DNS(Fallback DNS)，当主用DNS失效或不响应时，提供查询服务。  
可用于某些流量受限的DNS服务器，仅仅在主DNS服务器失效时提供查询服务，以减少流量消耗。

1. 设置指定DNS为后备DNS服务器  

    使用`-fallback`参数，指定特定的server为fallback DNS。  

    ```shell
    server -fallback
    ```
  
1. 等价配置方法：

    同时使用`-e -group fallback`配置项，等价上述配置。

    ```shell
    server -e -group fallback
    ```
