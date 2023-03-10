# SmartDNS 文档

SmartDNS文档仓库，采用mkdocs生成，代码仓包含中文，英文两个版本的文档。

## 文档开发步骤

1. 安装mkdocs工具：https://squidfunk.github.io/mkdocs-material/getting-started/

1. 下载文档代码

    ```shell
    git clone -b doc https://github.com/pymumu/smartdns.git
    ```

1. 启动Serve模式验证

    ```shell
    make serve
    ```

1. 启动English模式验证

   ```shell
   make serve-en
   ```

1. 浏览器打开http://127.0.0.1:8000

1. 安装markdown lint相关工具清除lint告警。

## 文档License

CC0 License
