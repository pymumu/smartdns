---
hide:
  - toc
---

# 规则组

smartdns支持规则组，不同的规则组之间隔离，方便按照域名或客户端匹配过滤规则。

相关的参数有

| 参数 | 功能 |
|--|--|
| group-begin [group-name] [-inherit group-name]| 规则组开始  
| group-end  | 规则组结束  
| group-match  | 匹配规则组条件，可以设置域名或客户端IP。
| conf-file -group  | 以指定规则组包含文件，等价group-begin, group-end  


通过group-match可以指定匹配规则，有客户端IP：`-client-ip cidr|ip-set|mac`，域名：`-domain`。

## 按域名或客户端IP匹配规则组

  ```
  # 规则开始，指定名称为rule。
  group-begin rule
  # 设置匹配规则，如下为匹配IP、MAC或者域名。
  group-match -client-ip 192.168.1.1/24 -domain a.com
  group-match -client-ip 01:02:03:04:05:06
  group-match -client-ip ip-set:clien-ip 
  group-match -domain domain-set:domain-list
  # 设置相关的规则
  address #
  # 规则结束
  group-end
  ```

## 继承组的配置

group-begin默认情况下继承当前组的配置，如果要指定继承不同组，可以使用`-inherit`指定继承配置的组。

  ```
  # 默认继承当前组的配置
  group-begin rule
  group-end

  # 设置none，表示不继承任何组，使用默认配置
  group-begin rule -inherit none
  gorup-end

  # 继承指定的组的配置
  group-begin rule -inherit another-group
  group-end
  ```

## 包含文件规则组

也可以包含外部文件处理规则组，方便维护管理。

主要文件包含外部文件，并且`-group`指定规则组名称

  ```
  conf-file client.conf -group rule
  ```

包含的规则文件，指定匹配条件

  ```
  group-match -client-ip 192.168.1.1/24 -domain a.com
  address #
  ```