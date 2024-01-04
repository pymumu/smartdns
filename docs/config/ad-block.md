---
hide:
  - toc
---

# 广告屏蔽

smartdns可以通过address选项来屏蔽广告。

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

## 使用域名集合

对于单个域名屏蔽，可以方便使用address参数屏蔽，对于较多的域名，可通过域名集合屏蔽，更加方便管理广告域名列表。

```shell
domain-set -name ad -file /path/to/adblock.list
address /domain-set:ad/#

```

adlobck.list的内容为每行一个域名。

```shell
a.com
b.com
...

```

## 使用社区已有smartdns广告过滤列表

社区针对smartdns提供了每日更新的广告列表文件，可以直接使用这些广告列表文件，smartdns可以通过conf-file选项包含广告屏蔽文件。另外在使用这些广告列表文件时，可以定期下载更新文件，并重启smartdns生效。

1. 下载配置文件到`/etc/smartdns`目录

    ```shell
    wget https://anti-ad.net/anti-ad-for-smartdns.conf -O /etc/smartdns/anti-ad-smartdns.conf
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
|[neodevhost](https://github.com/neodevpro/neodevhost/)|AdRules SmartDNS List|https://raw.githubusercontent.com/neodevpro/neodevhost/master/lite_smartdns.conf |

## 非smartdns列表

对于非smartdns的数据，可以通过简单的shell命令进行转换。

### hosts格式

如下面命令，可以使用`hosts-file`来指定hosts格式文件

```shell
hosts-file /etc/smartdns/anti-ad-smartdns.hosts
```

也可以通过如下命令将hosts文件转换为smartdns特有格式。

```shell
cat /path/to/hosts/file | grep -v "^#" | awk '{print "address /"$2"/#"}' > anti-ad-smartdns.conf
```

### dnsmasq格式

dnsmasq格式和smartdns类似，但不兼容，可以通过如下命令转换

```shell
cat /path/to/dnsmasq/file  | grep address | awk -F= '{print "address "$2"#"}' > anti-ad-smartdns.conf
```
