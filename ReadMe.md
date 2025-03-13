**[English](ReadMe_en.md)**

在SmartDNS基础上，domain-set增加geosite域名匹配规则文本文件的支持，以便实现域名服务器分组。

##域名规则支持以下几种匹配方式:
1) 以 domain: 开头，域匹配。e.g: domain:google.com 会匹配自身 google.com，以及其子域名 www.google.com, maps.l.google.com 等。
2) 以 full: 开头，完整匹配。e.g: full:google.com 只会匹配自身。
3) 以 keyword: 开头，关键字匹配。e.g: keyword:google.com 会匹配包含这个字段的域名，如 google.com.hk, www.google.com.hk。
4) 以 regexp: 开头，正则匹配。e.g: "regexp:\.goo.*\.com$" 匹配 "www.google.com" 或 "fonts.googleapis.com"，但不匹配 "google.com"。

如果没有指定匹配方式，默认为域匹配。

匹配方式按如下顺序生效: full、domain优先， regexp、keyword次之，regexp 和 keyword 规则生效顺序为规则导入的顺序。

##编译cre2:
```
apt-get install libssl-dev libre2-dev automake libtool texinfo
git clone https://github.com/marcomaggi/cre2.git
cd cre2
./autogen.sh
touch ./doc/version.texi
mkdir build && cd build
../configure
make
make install
ldconfig
```
##编译v2dat:
```
git clone https://github.com/urlesistiana/v2dat.git
cd v2dat
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o v2dat -trimpath -ldflags "-s -w -buildid=" .
```
##数据下载及转换：
```
wget https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
./v2dat unpack geosite -f google geosite.dat
```
##配置smartdns.conf：
```
domain-set -name geosite_google -type geosite -file /etc/smartdns/geosite_google.txt
nameserver /domain-set:geosite_google/google
server 8.8.8.8 -group google -exclude-default-group
```
SmartDNS官网：[https://pymumu.github.io/smartdns](https://pymumu.github.io/smartdns)

