---
hide:
  - toc
---

# 广告屏蔽

smartdns可以通过指定对应域名返回SOA用于广告屏蔽。

注意：openwrt有luci的方式，请参考openwrt屏蔽域名配置方法。

## 基本配置方法

1. 通过`address /domain/#`选项屏蔽广告，如。

    ```shell
    address /example.com/#
    ```

    address选项中:

    * /domain/为后缀匹配算法，范围包含其子域名。
    * 单独`#`表示同时屏蔽IPV4, IPV6，
    * 使用`#6`表示屏蔽IPV6
    * 使用`#4`表示屏蔽IPV4。
    * 使用`-`表示不屏蔽此域名。

1. 如单独屏蔽IPV6

    ```shell
    address /example.com/#6
    ```

1. 如果想不屏蔽某个子域名

    ```shell
    address /sub.example.com/-
    ```

## 使用社区已有smartdns广告过滤列表

社区针对smartdns提供了每日更新的广告列表文件，可以直接使用这些广告列表文件，smartdns可以通过conf-file选项包含广告屏蔽文件。另外在使用这些广告列表文件时，可以定期下载更新文件，并重启smartdns生效。

1. 下载配置文件到`/etc/smartdns`目录

    ```shell
    wget https://github.com/privacy-protection-tools/anti-AD/blob/master/anti-ad-smartdns.conf -o /etc/smartdns/anti-ad-smartdns.conf
    ```

1. 修改/etc/smartdns/smartdns.conf文件，包含上述配置文件

    ```shell
    conf-file /etc/smartdns/anti-ad-smartdns.conf
    ```

## 广告列表

|项目|说明|配置文件|
|--|--|--|
|[anti-AD](https://anti-ad.net/)|Anti Advertising for smartdns|https://anti-ad.net/anti-ad-for-smartdns.conf|
|[adrules](https://adrules.top/)|AdRules SmartDNS List|https://adrules.top/smart-dns.conf |

## 非smartdns列表

对于非smartdns的数据，可以通过简单的shell命令进行转换。

### hosts格式

如下面命令，可以将`/path/to/hosts/file`的文件（路径换成实际的文件），转换为smartdns支持的格式

```shell
cat /path/to/hosts/file | grep -v "^#" | awk '{print "address /"$2"/#"}' > anti-ad-smartdns.conf
```

### dnsmasq格式

dnsmasq格式和smartdns类似，但不兼容，可以通过如下命令转换

```shell
cat /path/to/dnsmasq/file  | grep address | awk -F= '{print "address "$2"#"}' > anti-ad-smartdns.conf
```
