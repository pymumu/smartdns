---
hide:
  - toc
---

# 测速模式

smartdns可修改测速模式，和数据响应模式。这两种模式影响查询的性能和效果。

|模式|参数|说明|
|---|---|---
|测速模式|speed-check-mode|smartdns速度检测模式
|响应模式|response-mode|结果回应模式|

## 速度检测模式

SmartDNS提供了两种测速模式，分别是ping和tcp。smartdns默认使用三次测速。第一次为ping，第二次为tcp的80端口，第三次为tcp的443端口，可通过speed-check-mode修改测速模式

1. 全局测速模式配置

    ```shell
    speed-check-mode ping,tcp:80,tcp:443
    speed-check-mode tcp:443,ping
    speed-check-mode none
    ```

    选项中:

    * ping表示使用ping模式，tcp:端口号，表示使用tcp链接对应的端口
    * none表示不进行测速
    * 测速选项的触发: 当配置3种测速模式后，smartdns首先用第一种，200ms后，用第二种，400ms后用第三种。

1. 单域名测速模式配置

    ```shell
    domain-rule /example.com/ -speed-check-mode ping,tcp:80,tcp:443
    ```

1. 对应端口查询时关闭测速

    ```shell
    bind [::]:53 -no-speed-check
    ```

1. 额外的

    如果分流的域名通过转发程序转发，则考虑关闭转发域名的测速功能，避免测速和出口不一致导致的体验反作用，关闭特定域名的测速方式如下：

    ```shell
    domain-rule /example.com/ -speed-check-mode none
    ```

## 响应模式配置

Smartdns支持通过`response-mode`设置首次请求响应模式，这三中模式影响查询结果和响应时间，smartdns默认使用了优化方案，但用户也可根据需要进行修改；这三种模式对应的功能和性能如下：

|模式|配置项|时延|结果|说明
|---|---|---|---|---
|最快ping响应地址模式|first-ping|适中|可能次佳|DNS上游最快查询时延+ping时延最短，查询等待与链接体验最佳。（当前默认）
|最快IP地址模式|fastest-ip|长|最佳|查询到的所有IP地址中ping最短的IP。DNS查询时间最长，IP链接最短。（之前模式）
|最快响应的DNS模式|fastest-response|短|可能最差|DNS查询等待时间最短。

对于开启了缓存功能后，缓存后的数据，无论使用哪种方式，其结果时最佳的，所以不建议关闭缓存。
