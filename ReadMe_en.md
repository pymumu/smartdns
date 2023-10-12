On the basis of SmartDNS, domain-set adds support for geosite domain name matching rule.

# How to use
```shell
Configure in smartdns.conf, such as 
domain-set -name google -type geosite -file /etc/smartdns/geosite_google.txt 
nameserver /domain-set:google/google

Domain name rules support the following matching methods: 
1) Domains start with domain:. e.g: domain: google.com matches its own google.com, as well as its subdomains www.google.com, maps.l.google.com, etc. 
2) Start with full:, complete match. e.g: full:google.com will only match itself. 
3) Start with keyword:, keyword match. e.g: keyword:google.com will match domain names that contain this field, such as google.com.hk, www.google.com.hk. 
4) Start with regexp:, regular matching. e.g: "regexp:.goo.*.com$" matches "www.google.com" or "fonts.googleapis.com", but does not match "google.com".

If no matching method is specified, the default is domain matching.
The matching method takes effect in the following order: full, domain first, regexp, keyword second, regexp and keyword rules take effect in the order of rule import.

Data download and conversion: 
geosite.dat domain rule data download: https://github.com/Loyalsoldier/v2ray-rules-dat 
Geosite.dat Convert Data to Text Format Tool: https://github.com/urlesistiana/v2dat

SmartDNS official website: https://pymumu.github.io/smartdns
