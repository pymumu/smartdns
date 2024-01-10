---
hide:
  - toc
---

# 规则组

smartdns支持规则组，不同的规则组之间隔离，方便按照域名或客户端匹配过滤规则。

相关的参数有

| 参数 | 功能 |
|--|--|
| group-begin [-g\|group group-name] | 规则组开始  
| group-end  | 规则组结束  
| group-match  | 匹配规则组条件，可以设置域名或客户端IP。
| conf-file -group  | 以指定规则组包含文件，等价group-begin, group-end  


通过group-match可以指定匹配规则，有客户端IP：`-client-ip cidr`，域名：`-domain`。

## 按域名或客户端IP匹配规则组

  ```
  # 规则开始，指定名称为rule。
  group-begin rule
  # 设置匹配规则，如下为匹配IP或者域名。
  group-match -client-ip 192.168.1.1/24 -domain a.com
  # 设置相关的规则
  address #
  # 规则结束
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