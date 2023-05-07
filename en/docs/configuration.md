---
hide:
  - navigation
  - toc
---

# Configurations

|parameter|Parameter function|Default value|Value type|Example|
|--|--|--|--|--|
|server-name|DNS name|host name/smartdns|any string like hostname|server-name smartdns
|bind|DNS listening port number|[::]:53|Support binding multiple ports<br />`IP:PORT@DEVICE`: server IP, port number, and device. <br />`[-group]`: The DNS server group used when requesting. <br />`[-no-rule-addr]`: Skip the address rule. <br />`[-no-rule-nameserver]`: Skip the Nameserver rule. <br />`[-no-rule-ipset]`: Skip the Ipset or nftset rules. <br />`[-no-rule-soa]`: Skip address SOA(#) rules.<br />`[-no-dualstack-selection]`: Disable dualstack ip selection.<br />`[-no-speed-check]`: Disable speed measurement. <br />`[-no-cache]`: stop caching <br />[-force-aaaa-soa]: force AAAA query return SOA, <br />[-ipset]: set IPSet, refer to ipset option <br />[-nftset]: set nftset, refer to nftset option |bind :53@eth0
|bind-tcp|TCP mode DNS listening port number|[::]:53|Support binding multiple ports<br />`IP:PORT@DEVICE`: server IP, port number and device. <br />`[-group]`: The DNS server group used when requesting. <br />`[-no-rule-addr]`: Skip the address rule. <br />`[-no-rule-nameserver]`: Skip the Nameserver rule. <br />`[-no-rule-ipset]`: Skip the ipset or nftset rules. <br />`[-no-rule-soa]`: Skip address SOA(#) rules.<br />`[-no-dualstack-selection]`: Disable dualstack ip selection.<br />`[-no-speed-check]`: Disable speed measurement. <br />`[-no-cache]`: stop caching <br />[-force-aaaa-soa]: force AAAA query return SOA, <br />[-ipset]: set IPSet, refer to ipset option <br />[-nftset]: set nftset, refer to nftset option |bind-tcp :53
|bind-tls|DOT mode DNS listening port number|[::]:853|Support binding multiple ports<br />`IP:PORT@DEVICE`: server IP, port number and device. <br />`[-group]`: The DNS server group used when requesting. <br />`[-no-rule-addr]`: Skip the address rule. <br />`[-no-rule-nameserver]`: Skip the Nameserver rule. <br />`[-no-rule-ipset]`: Skip the ipset or nftset rules. <br />`[-no-rule-soa]`: Skip address SOA(#) rules.<br />`[-no-dualstack-selection]`: Disable dualstack ip selection.<br />`[-no-speed-check]`: Disable speed measurement. <br />`[-no-cache]`: stop caching <br />[-force-aaaa-soa]: force AAAA query return SOA, <br />[-ipset]: set IPSet, refer to ipset option <br />[-nftset]: set nftset, refer to nftset option |bind-tcp :853
|bind-cert-file|SSL Certificate file path|smartdns-cert.pem|path| bind-cert-file cert.pem |
|bind-cert-key-file|SSL Certificate key file path|none|smartdns-key.pem| bind-cert-key-file key.pem |
|bind-cert-key-pass|SSL Certificate key file password|none|string| bind-cert-key-pass password |
|cache-size|Domain name result cache number|Auto: Set cache site by memory size. |integer|cache-size 512
|cache-persist|enable persist cache|Auto: Enabled if the location of `cache-file` has more than 128MB of free space.|[yes\|no]|cache-persist yes
|cache-file|cache persist file|/tmp/<br />smartdns.cache|path|cache-file /tmp/smartdns.cache
|cache-checkpoint-time| cache persist time | 0 | 0 or greater than 120, 0: disable， other: persis time in seconds | cache-checkpoint-time 0
|tcp-idle-time|TCP connection idle timeout|120|integer|tcp-idle-time 120
|rr-ttl|Domain name TTL|Remote query result|number greater than 0|rr-ttl 600
|rr-ttl-min|Domain name Minimum TTL|Remote query result|number greater than 0|rr-ttl-min 60
|local-ttl|ttl for address and host|rr-ttl-min|number greater than 0|local-ttl 600
|rr-ttl-reply-max|Domain name Minimum Reply TTL|Remote query result|number greater than 0|rr-ttl-reply-max 60
|rr-ttl-max|Domain name Maximum TTL|Remote query result|number greater than 0|rr-ttl-max 600
|max-reply-ip-num|Maximum number of IPs returned to the client|8|number of IPs, 1~16 |max-reply-ip-num 1
|log-level|log level|error|off,fatal,error,warn,notice,info,debug|log-level error
|log-file|log path|/var/log/<br />smartdns/<br />smartdns.log|File Pah|log-file /var/log/smartdns/smartdns.log
|log-size|log size|128K|number+K,M,G|log-size 128K
|log-num|archived log number|2 for openwrt, 8 for other system|Integer, 0 means turn off the log|log-num 2
|log-file-mode|archived log file mode|0640|Integer|log-file-mode 644
|log-console|enable output log to console|no|[yes\|no]|log-console yes
|audit-enable|audit log enable|no|[yes\|no]|audit-enable yes
|audit-file|audit log file|/var/log/<br />smartdns/<br />smartdns-audit.log|File Path|audit-file /var/log/smartdns/smartdns-audit.log
|audit-size|audit log size|128K|number+K,M,G|audit-size 128K
|audit-num|archived audit log number|2|Integer, 0 means turn off the log|audit-num 2
|audit-file-mode|archived audit log file mode|0640|Integer|audit-file-mode 644
|audit-console|enable output audit log to console|no|[yes\|no]|audit-console yes
|conf-file|additional conf file|None|File path|conf-file /etc/smartdns/smartdns.more.conf
|server|Upstream UDP DNS server|None|Repeatable <br />`[ip][:port]\|URL`: Server IP, port optional OR URL. <br />`[-blacklist-ip]`: The "-blacklist-ip" parameter is to filtering IPs which is configured by "blacklist-ip". <br />`[-whitelist-ip]`: whitelist-ip parameter specifies that only the IP range configured in whitelist-ip is accepted. <br />`[-group [group] ...]`: The group to which the DNS server belongs, such as office, foreign, use with nameserver. <br />`[-exclude-default-group]`: Exclude DNS servers from the default group. <br />`[-set-mark mark]`: set mark on packets <br /> `[-proxy name]`: set proxy server <br /> `[-bootstrap-dns]`: set as bootstrap dns server <br />[-subnet]：set per server edns-client-subnet | server 8.8.8.8:53 -blacklist-ip<br />server tls://8.8.8.8
|server-tcp|Upstream TCP DNS server|None|Repeatable <br />`[ip][:port]`: Server IP, port optional. <br />`[-blacklist-ip]`: The "-blacklist-ip" parameter is to filtering IPs which is configured by "blacklist-ip". <br />`[-whitelist-ip]`: whitelist-ip parameter specifies that only the IP range configured in whitelist-ip is accepted. <br />`[-group [group] ...]`: The group to which the DNS server belongs, such as office, foreign, use with nameserver. <br />`[-exclude-default-group]`: Exclude DNS servers from the default group <br />`[-set-mark mark]`: set mark on packets <br /> `[-proxy name]`: set proxy server <br /> `[-bootstrap-dns]`: set as bootstrap dns server <br />[-subnet]：set per server edns-client-subnet | server-tcp 8.8.8.8:53
|server-tls|Upstream TLS DNS server|None|Repeatable <br />`[ip][:port]`: Server IP, port optional. <br />`[-spki-pin [sha256-pin]]`: TLS verify SPKI value, a base64 encoded SHA256 hash<br />`[-host-name]`:TLS Server name. `-` to disable SNI name.<br />`[-tls-host-verify]`: TLS cert hostname to verify. <br />`-no-check-certificate:`: No check certificate. <br />`[-blacklist-ip]`: The "-blacklist-ip" parameter is to filtering IPs which is configured by "blacklist-ip". <br />`[-whitelist-ip]`: whitelist-ip parameter specifies that only the IP range configured in whitelist-ip is accepted. <br />`[-group [group] ...]`: The group to which the DNS server belongs, such as office, foreign, use with nameserver. <br />`[-exclude-default-group]`: Exclude DNS servers from the default group <br /> `[-set-mark mark]`: set mark on packets <br /> `[-proxy name]`: set proxy server <br /> `[-bootstrap-dns]`: set as bootstrap dns server <br />[-subnet]：set per server edns-client-subnet | server-tls 8.8.8.8:853
|server-https|Upstream HTTPS DNS server|None|Repeatable <br />`https://[host][:port]/path`: Server IP, port optional. <br />`[-spki-pin [sha256-pin]]`: TLS verify SPKI value, a base64 encoded SHA256 hash<br />`[-host-name]`:TLS Server name<br />`[-http-host]`: http header host. <br />`[-tls-host-verify]`: TLS cert hostname to verify. <br />`-no-check-certificate:`: No check certificate. <br />`[-blacklist-ip]`: The "-blacklist-ip" parameter is to filtering IPs which is configured by "blacklist-ip". <br />`[-whitelist-ip]`: whitelist-ip parameter specifies that only the IP range configured in whitelist-ip is accepted. <br />`[-group [group] ...]`: The group to which the DNS server belongs, such as office, foreign, use with nameserver. <br />`[-exclude-default-group]`: Exclude DNS servers from the default group <br /> `[-set-mark mark]`: set mark on packets <br /> `[-proxy name]`: set proxy server <br /> `[-bootstrap-dns]`: set as bootstrap dns server <br />[-subnet]：set per server edns-client-subnet | server-https <https://cloudflare-dns.com/dns-query>
|proxy-server| proxy server | None | Repeatable. <br />`proxy-server URL` <br />[URL]: `[socks5\|http]://[username:password@]host:port`<br />[-name]:  proxy server name. |proxy-server socks5://user:pass@1.2.3.4:1080 -name proxy|
|speed-check-mode|Speed ​​mode|None|[ping\|tcp:[80]\|none]|speed-check-mode ping,tcp:80,tcp:443
|response-mode|First query response mode|first-ping|Mode: [first-ping\|fastest-ip\|fastest-response]<br /> [first-ping]: The fastest dns + ping response mode, DNS query delay + ping delay is the shortest;<br />[fastest-ip]: The fastest IP address mode, return the fastest ip address, may take some time to test speed. <br />[fastest-response]: The fastest response DNS result mode, the DNS query waiting time is the shortest. | response-mode first-ping |
|expand-ptr-from-address| Whether to expand the address record corresponding to PTR record | no | [yes\|no] | expand-ptr-from-address yes |
|address|Domain IP address|None|address /domain/[ip\|-\|-4\|-6\|#\|#4\|#6], `-` for ignore, `#` for return SOA, `4` for IPV4, `6` for IPV6| address /www.example.com/1.2.3.4
|cname|set cname to domain| None | cname /domain/target <br />- for ignore <br />set cname to domain. | cname /www.example.com/cdn.example.com |
|dns64|dns64 translation | None | dns64 ip-prefix/mask <br /> ipv6 prefix and mask. | dns64 64:ff9b::/96 |
|edns-client-subnet| DNS ECS | None |edns-client-subnet ip-prefix/mask <br /> set EDNS client subnet | ip-prefix/mask 1.2.3.4/23 |
|nameserver|To query domain with specific server group|None|nameserver /domain/[group\|-], `group` is the group name, `-` means ignore this rule, use the `-group` parameter in the related server|nameserver /www.example.com/office
|ipset|Domain IPSet|None|ipset /domain/[ipset\|-\|#[4\|6]:[ipset\|-][,#[4\|6]:[ipset\|-]]], `-` for ignore|ipset /www.example.com/#4:dns4,#6:-
|ipset-timeout|ipset timeout enable|no|[yes\|no]|ipset-timeout yes
|ipset-no-speed|When speed check fails, set the ip address of the domain name to the ipset | None | ipset \| #[4\|6]:ipset | ipset-no-speed #4:ipset4,#6:ipset6 <br /> ipset-no-speed ipset|
|nftset|Domain nftset|None|nftset /domain/[#4\|#6\|-]:[family#nftable#nftset\|-][,#[4\|6]:[family#nftable#nftset\|-]]]<br /> `-` to ignore<br />the valid families are inet and ip for ipv4 addresses while the valid ones are inet and ip6 for ipv6 addresses <br />due to the limitation of nftable <br />two types of addresses have to be stored in two sets|nftset /www.example.com/#4:inet#tab#dns4,#6:-
|nftset-timeout|nftset timeout enable|no|[yes\|no]|nftset-timeout yes
|nftset-no-speed|When speed check fails, set the ip address of the domain name to the nftset | None | nftset-no-speed [#4\|#6]:[family#nftable#nftset][,#[4\|6]:[family#nftable#nftset]]] <br />the valid families are inet and ip for ipv4 addresses while the valid ones are inet and ip6 for ipv6 addresses <br />due to the limitation of nftable <br />two types of addresses have to be stored in two sets| nftset-no-speed #4:inet#tab#set4|
|nftset-debug|nftset debug enable|no|[yes\|no]|nftset-debug yes
|domain-rules|set domain rules|None|domain-rules /domain/ [-rules...]<br />[-c\|-speed-check-mode]: set speed check mode, same as parameter `speed-check-mode`<br />[-a\|-address]: same as  parameter `address` <br />[-n\|-nameserver]: same as parameter `nameserver`<br />[-p\|-ipset]: same as parameter `nftset`<br />[-t\|-nftset]: same as parameter `nftset`<br />[-d\|-dualstack-ip-selection]: same as parameter `dualstack-ip-selection`<br />  [-no-serve-expired]: disable serve expired<br />[-rr-ttl\|-rr-ttl-min\|-rr-ttl-max]: same as parameter: `rr-ttl`, `rr-ttl-min`, `rr-ttl-max`<br />[-no-cache]：not cache this domain.<br />[-r\|-response-mode]：response mode, same as `response-mod`e<br />[-delete]: delete rule|domain-rules /www.example.com/ -speed-check-mode none
| domain-set | collection of domains|None| domain-set [options...]<br />[-n\|-name]: name of set <br />[-t\|-type] [list]: set type, only support list, one domain per line <br />[-f\|-file]: file path of domain set<br /> used with address, nameserver, ipset, nftset, example: /domain-set:[name]/ | domain-set -name set -type list -file /path/to/list <br /> address /domain-set:set/1.2.4.8 |
|bogus-nxdomain|bogus IP address|None|[IP/subnet], Repeatable| bogus-nxdomain 1.2.3.4/16
|ignore-ip|ignore ip address|None|[ip/subnet], Repeatable| ignore-ip 1.2.3.4/16
|whitelist-ip|ip whitelist|None|[ip/subnet], Repeatable, When the filtering server responds IPs in the IP whitelist, only result in whitelist will be accepted| whitelist-ip 1.2.3.4/16
|blacklist-ip|ip blacklist|None|[ip/subnet], Repeatable, When the filtering server responds IPs in the IP blacklist, The result will be discarded directly| blacklist-ip 1.2.3.4/16
|force-AAAA-SOA|force AAAA query return SOA|no|[yes\|no]|force-AAAA-SOA yes
|force-qtype-SOA|force specific qtype return SOA|qtype id|[qtypeid \| ...]|force-qtype-SOA 65 28
|prefetch-domain|domain prefetch feature|no|[yes\|no]|prefetch-domain yes
|dnsmasq-lease-file|Support reading dnsmasq dhcp file to resolve local hostname|None|dnsmasq dhcp lease file| dnsmasq-lease-file /var/lib/misc/dnsmasq.leases
|serve-expired|Cache serve expired feature|yes|[yes\|no], Attempts to serve old responses from cache with a TTL of 0 in the response without waiting for the actual resolution to finish.|serve-expired yes
|serve-expired-ttl|Cache serve expired limit TTL|0|second, 0: disable, > 0  seconds after expiration|serve-expired-ttl 0
|serve-expired-reply-ttl|TTL value to use when replying with expired data|5|second, 0: disable, > 0  seconds after expiration|serve-expired-reply-ttl 30
|serve-expired-prefetch-time| Prefetch time when serve expired | 28800 | second，prefetch time | serve-expired-prefetch-time 86400 |
|dualstack-ip-selection|Dualstack ip selection|yes|[yes\|no]|dualstack-ip-selection yes
|dualstack-ip-selection-threshold|Dualstack ip select thresholds|10ms|millisecond|dualstack-ip-selection-threshold [0-1000]
|user|run as user|root|user [username]|user nobody
|ca-file|certificate file|/etc/ssl/certs/<br />ca-certificates.crt|path|ca-file /etc/ssl/certs/ca-certificates.crt
|ca-path|certificates path|/etc/ssl/certs|path|ca-path /etc/ssl/certs
