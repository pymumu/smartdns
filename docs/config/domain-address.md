---
hide:
  - toc
---

# 指定域名地址

address除了可以设置屏蔽广告外，还可以指定域名的IP地址。

## 基本配置方法

1. 通过`address /domain/ip`选项指定IP，如。

    ```shell
    address /example.com/1.2.3.4
    address /example.com/4.5.6.7,8.9.10.11,12.13.14.15
    ```

    address选项中:

    * /domain/为后缀匹配算法，范围包含其子域名。
    * ip: 可以为IPV6，或IPV4地址，可以指定多个IP地址，如果有多个IP地址，查询的时候，将会进行随机排序。

1. 指定IPV6

    ```shell
    address /example.com/::1
    ```

1. 前缀通配与主域名匹配

    ```shell
    // 通配
    *-a.example.com 
    // 仅匹配子域名
    *.example.com
    // 仅匹配主域名
    -.example.com
    ```

    注意：* 和 - 仅支持写在域名开头。其他位置的写法均不支持。

## 自动扩展address对应的PTR记录

如果想扩展上述address对应的PTR记录，可以使用`expand-ptr-from-address`开关开启自动扩展。`expand-ptr-from-address`参数可以重复设置，参数对设置后的`address`生效。

```shell
expand-ptr-from-address yes
address /example.com/1.2.3.4
expand-ptr-from-address no
```
