**[English](ReadMe_en.md)**

在SmartDNS基础上，domain-set增加geosite域名匹配规则文本文件的支持，以便实现域名服务器分组。

## 使用方法

```shell

在smartdns.conf中配置，如
  domain-set -name google -type geosite -file /etc/smartdns/geosite_google.txt
  nameserver /domain-set:google/google

域名规则支持以下几种匹配方式:
1) 以 domain: 开头，域匹配。e.g: domain:google.com 会匹配自身 google.com，以及其子域名 www.google.com, maps.l.google.com 等。
2) 以 full: 开头，完整匹配。e.g: full:google.com 只会匹配自身。
3) 以 keyword: 开头，关键字匹配。e.g: keyword:google.com 会匹配包含这个字段的域名，如 google.com.hk, www.google.com.hk。
4) 以 regexp: 开头，正则匹配。e.g: "regexp:\.goo.*\.com$" 匹配 "www.google.com" 或 "fonts.googleapis.com"，但不匹配 "google.com"。

如果没有指定匹配方式，默认为域匹配。

匹配方式按如下顺序生效: full、domain优先， regexp、keyword次之，regexp 和 keyword 规则生效顺序为规则导入的顺序。

数据下载及转换：
geosite.dat域名规则数据下载：https://github.com/Loyalsoldier/v2ray-rules-dat
geosite.dat数据转换为文本格式工具: https://github.com/urlesistiana/v2dat

编译cre2:
apt-get install libssl-dev libre2-dev automake libtool texinfo
cd smartdns/cre2
./autogen.sh
cd build
../configure
make install
ldconfig

SmartDNS官网：[https://pymumu.github.io/smartdns](https://pymumu.github.io/smartdns)

