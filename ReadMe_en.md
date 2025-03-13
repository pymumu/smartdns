Based on SmartDNS, the domain-set adds support for geosite domain matching rule text files to enable grouping of domain servers.

###Domain rules support the following matching methods:

Starting with domain: for domain matching. e.g., domain:google.com will match google.com itself and its subdomains like www.google.com, maps.l.google.com, etc.

Starting with full: for exact matching. e.g., full:google.com will only match itself.

Starting with keyword: for keyword matching. e.g., keyword:google.com will match domains containing this field, such as google.com.hk, www.google.com.hk.

Starting with regexp: for regular expression matching. e.g., "regexp:\.goo.*\.com$" matches www.google.com or fonts.googleapis.com but not google.com.

If no matching method is specified, domain matching is used by default.

The matching methods take effect in the following order: full and domain have priority, followed by regexp and keyword. The order of effectiveness for regexp and keyword rules depends on their import sequence.

###Compile cre2:
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
###Compile v2dat:
```
git clone https://github.com/urlesistiana/v2dat.git
cd v2dat
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o v2dat -trimpath -ldflags "-s -w -buildid="
```
###Data download and conversion:
```
wget https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
./v2dat unpack geosite -f google geosite.dat
```
###Configure smartdns.conf:
```
domain-set -name geosite_google -type geosite -file /etc/smartdns/geosite_google.txt
nameserver /domain-set:geosite_google/google
server 8.8.8.8 -group google -exclude-default-group
```
SmartDNS official website: https://pymumu.github.io/smartdns