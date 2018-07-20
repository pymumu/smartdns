SmartDNS
==============
SmartDNS是一个运行在本地的DNS服务器，SmartDNS接受本地客户端的DNS查询请求，从多个上游DNS服务器获取DNS查询结果，并将访问速度最快的结果返回个客户端，避免DNS污染，提高网络访问速度。
同时支持指定特定域名IP地址，并高性匹配，达到过滤广告的效果。

特性
--------------
1. **多DNS上游服务器**  
   支持配置多个上游DNS服务器，并同时进行查询，即使其中有DNS服务器异常，也不会影响查询。  

1. **返回最快IP地址**  
   支持从域名所属IP地址列表中查找到访问速度最快的IP地址，并返回给客户端，避免DNS污染，提高网络访问速度。

1. **支持非标准端口**  
   支持非53端口查询，支持TCP查询，有效避免DNS污染。

1. **特定域名IP地址指定**  
   支持指定域名的IP地址，达到广告过滤效果，避免恶意网站的效果。

1. **域名高性能后缀匹配**  
   支持域名后缀匹配模式，简化过滤配置，过滤20万条记录时间<1ms

1. **Linux多平台支持**  
   支持标准Linux系统（树莓派），openwrt系统各种固件，华硕路由器原生固件。

1. **支持IPV4, IPV6双栈**  
   支持IPV4，IPV6网络，支持查询A, AAAA记录。

1. **高性能，占用资源少**  
   多线程异步IO模式，cache缓存查询结果。

架构
-------------
![Architecture](Doc/architecture.png)  
1. SmartDNS接收本地网络设备的DNS查询请求，如PC，手机的查询请求。  
2. SmartDNS将查询请求发送到多个上游DNS服务器，可采用标准UDP查询，非标准端口UDP查询，及TCP查询。  
3. 上游DNS服务器返回域名对应的Server IP地址列表。SmartDNS检测与本地网络访问速度最快的Server IP。  
4. 将访问速度最快的Server IP返回给本地客户端。  


使用
==============
下载配套安装包
--------------
下载配套版本的SmartDNS安装包，对应安装包配套关系如下。

|系统 |安装包|说明
|-----|-----|-----
|标准Linux系统（树莓派）| smartdns.xxxxxxxx.armhf.deb|支持树莓派Raspbian stretch，Debian 9系统。
|华硕原生固件|asusware.mipsbig.tar.gz|支持MIPS大端架构的系统，如RT-AC55U, RT-AC66U.
|openwrt 15.01|smartdns.xxxxxxxx.ar71xx.ipk|支持AR71XX MIPS系统
|openwrt LEDE|smartdns.1.2xxxxxxxx.mips_24kc.ipk|支持AR71XX MIPS系统。
|openwrt LEDE|smartdns.1.2xxxxxxxx.mipsel_24kc.ipk|支持

标准Linux系统安装（树莓派）
--------------
1. 安装
```
dpkg -i smartdns.xxxxxxxx.armhf.deb
```
2. 修改配置
```
vi /etc/smartdns/smartdns.conf
```
3. 启动服务
```
systemctl enable smartdns
systemctl start smartdns
```
4. 修改本地路由器DNS指向树莓派  
* 登录到本地网络的路由器中，配置树莓派分配静态IP地址。
* 修改WAN口或者DHCP DNS为树莓派IP地址。  
 注意：  
 I. 每款路由器配置方法不尽相同，请百度搜索相关的配置方法。  
 II.  华为等路由器可能不支持配置DNS为本地IP，请修改PC端，手机端DNS服务器为树莓派IP。


openwrt/LEDE
--------------
1. 安装
将软件使用winscp上传到路由器的/root目录，执行如下命令安装
```
opkg install smartdns.xxxxxxxx.xxxx.ipk
```

2. 修改配置
```
vi /etc/smartdns/smartdns.conf
```
3. 启动服务
```

```

华硕路由器原生固件
--------------
在使用此软件时，需要确认路由器是否支持U盘，并准备好U盘一个。

1. 解压安装包到U盘根目录，其目录格式如下。（此处仅列出smartdns相关文件）
```
U盘
 └── asusware.mipsbig
          ├── bin
          ├── etc
          |    ├── smartdns 
          |    |     └── smartdns.conf
          |    └── init.d
          |          └── S50smartdns         
          ├── lib
          ├── sbin
          ├── usr
          |    └── sbin
          |          └── smartdns     
          ....
```
2. 修改配置
```
vi asusware.mipsbig/etc/smartdns/smartdns.conf
```
3. 启动服务
将U盘插入路由器后方USB插口，并重启路由器。

4. 检测DNS服务是否生效
待路由器启动后，使用nslookup查询域名，看命令结果中的`服务器`项目是否显示为`smartdns`，如显示smartdns则表示生效
```
C:\Users\meikechong>nslookup www.baidu.com
服务器:  smartdns
Address:  192.168.1.1

非权威应答:
名称:    www.a.shifen.com
Address:  14.215.177.39
Aliases:  www.baidu.com
```

配置参数
==============
|参数|功能|默认值|配置值|例子|
|--|--|--|--|--|
|server-name|DNS服务器名称|操作系统主机名/smartdns|符合主机名规格的字符串|server-name smartdns
|bind|DNS监听端口号|[::]:53|IP:PORT|bind 192.168.1.1:53
|cache-size|域名结果缓存个数|512|数字|cache-size 512
|rr-ttl|域名结果TTL|远程查询结果|大于0的数字|rr-ttl 600
|rr-ttl-min|允许的最小TTL值|远程查询结果|大于0的数字|rr-ttl-min 60
|rr-ttl-max|允许的最大TTL值|远程查询结果|大于0的数组|rr-ttl-max 600
|log-level|设置日志级别|error|error,warn,info,debug|log-level error
|log-file|日志文件路径|/var/log/smartdns.log|路径|log-file /var/log/smartdns.log
|log-size|日志大小|128K|数字+K,M,G|log-size 128K
|log-num|日志归档个数|2|数字|log-num 2
|server|上游UDP DNS|114.114.114.114|[ip][:port]，可重复| server 8.8.8.8:53
|server-tcp|上游TCP DNS|无|[IP][:port]，可重复| server-tcp 8.8.8.8:53
|address|指定域名IP地址|无|address /domain/ip| address /www.example.com/1.2.3.4

捐助
==============



说明
==============
目前代码未开源，后续根据情况开源。

  







