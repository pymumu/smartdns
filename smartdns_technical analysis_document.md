
## SmartDNS 技术分析文档

### 1. 引言

SmartDNS 是一个高性能的本地 DNS 服务器，其核心目标是为用户提供最快的域名解析结果，从而优化互联网访问体验。它通过从多个上游 DNS 服务器并发查询，并结合灵活的测速机制和规则引擎，智能地选择最佳 IP 地址返回给客户端。

**核心特性包括：**

*   **并发与优选**：同时向上游服务器查询，并根据配置的测速模式（如 PING、TCP 探测）和响应模式（如最快 IP、首个 PING 通 IP）返回最优结果。
*   **多协议支持**：支持传统的 UDP/TCP DNS，以及加密的 DoT (DNS over TLS), DoH (DNS over HTTPS), DoQ (DNS over QUIC) 和 DoH3 (DNS over HTTP/3) 协议，增强了查询的私密性和安全性。
*   **高级路由与规则引擎**：
    *   基于域名、域名组 (`domain-set`)、Geosite 规则、客户端 IP/MAC 实现精细化的 DNS 路由。
    *   可为特定域名指定静态 IP (`address`)、CNAME、SRV、HTTPS 记录。
    *   可将特定域名解析结果送入 ipset 或 nftables set，方便与防火墙联动。
*   **强大的缓存机制**：内置高效缓存，支持持久化、预取 (`prefetch-domain`) 和过期服务 (`serve-expired`)，减少延迟。
*   **灵活的配置**：通过 `smartdns.conf` 文件提供丰富的配置选项，满足各种复杂场景需求。
*   **跨平台**：支持 Linux (包括 OpenWrt、树莓派等嵌入式设备)、Windows (通过 WSL) 等多种平台。
*   **轻量与高效**：采用多线程异步 I/O 模型，资源占用少。
*   **插件扩展**：支持通过插件扩展功能，例如 `smartdns-ui` 提供了 Web 管理界面。

本技术文档旨在深入分析 SmartDNS 的配置文件、配置加载机制、核心服务流程以及关键特性的实现原理，帮助开发者和高级用户更好地理解和使用 SmartDNS。

### 2. 配置文件 (`smartdns.conf`) 详解

SmartDNS 的所有行为都通过其主配置文件 `smartdns.conf` (通常位于 `/etc/smartdns/smartdns.conf` 或编译时指定的路径) 来控制。该文件采用纯文本格式，以 `#` 开头的行为注释行。配置项通常由指令和参数构成。

#### 2.1 基本服务配置

这类配置定义了 SmartDNS 服务自身的基础运行参数。

*   **`server-name <name>`**
    *   **描述**：设置 DNS 服务器的名称，主要用于某些 DNS 协议（如 TXT 记录查询服务器版本）或日志中识别。
    *   **参数**：`<name>` - 自定义的服务器名称。
    *   **默认值**：系统主机名。
    *   **示例**：`server-name my-smartdns-server`

*   **`resolv-hostname [yes|no]`**
    *   **描述**：是否解析本机的完整主机名 (hostname) 到其 IP 地址。如果设置为 `yes`，SmartDNS 会尝试将本机的主机名解析为一个 A/AAAA 记录。
    *   **默认值**：未明确配置则可能为 `no` 或取决于系统。
    *   **示例**：`resolv-hostname yes`

*   **`user <username>`**
    *   **描述**：指定 SmartDNS 服务运行的用户身份。出于安全考虑，建议在初始化 (如绑定特权端口) 后切换到非 root 用户运行。
    *   **参数**：`<username>` - 系统中存在的用户名。
    *   **默认值**：启动 SmartDNS 的用户，通常是 root。
    *   **示例**：`user nobody`

*   **`conf-file <file_path> [-group <group_name>]`**
    *   **描述**：包含另一个配置文件。这允许用户将复杂的配置拆分成多个小文件，方便管理。支持使用 `glob` 通配符 (如 `conf-file *.conf`)。
    *   **参数**：
        *   `<file_path>`: 要包含的配置文件的路径。
        *   `-group <group_name>` (可选): 如果指定，则被包含文件中的规则仅应用于名为 `<group_name>` 的服务器组的上下文。这允许为不同的服务器组定义独立的规则集。
    *   **示例**：
        ```
        conf-file /etc/smartdns/custom/blacklist.conf
        conf-file /etc/smartdns/ads-rules.conf -group adblock-group
        conf-file /etc/smartdns/domains.d/*.conf
        ```

*   **`bind <[IP]:[port][@device]> [options...]`**
*   **`bind-tcp <[IP]:[port][@device]> [options...]`**
*   **`bind-tls <[IP]:[port][@device]> [options...]`**
*   **`bind-https <[IP]:[port][@device]> [options...]`**
    *   **描述**：指定 SmartDNS 监听 DNS 请求的本地 IP 地址和端口。可以配置多个 `bind` 指令以监听不同的地址、端口或协议。
        *   `bind`: 监听 UDP DNS 请求。
        *   `bind-tcp`: 监听 TCP DNS 请求。
        *   `bind-tls`: 监听 DoT (DNS over TLS) 请求。需要配合 `bind-cert-key-file` 和 `bind-cert-file`。
        *   `bind-https`: 监听 DoH (DNS over HTTPS) 请求。需要配合 `bind-cert-key-file` 和 `bind-cert-file`。
    *   **参数**：
        *   `<[IP]:[port]>`：监听的 IP 地址和端口。
            *   `IP` 可以是 IPv4 或 IPv6 地址。`:` 表示监听所有可用 IPv4 地址，`[::]` 表示监听所有可用 IPv6 地址。
            *   `port` 是监听的端口号，默认为 53 (对于 UDP/TCP) 或 853 (TLS) 或 443 (HTTPS)。
            *   `@device` (可选): 将监听绑定到特定的网络接口 (如 `@eth0`)。
    *   **`options` (可为每个 `bind` 单独设置，覆盖全局或组设置)**:
        *   `-group <group_name>`: 将此监听端口收到的请求默认归属到指定的服务器规则组 `<group_name>`。客户端规则可以覆盖此设置。
        *   `-no-rule-addr`: 对于此监听端口收到的请求，跳过 `address` 规则的匹配。
        *   `-no-rule-nameserver`: 跳过 `nameserver` 规则的匹配。
        *   `-no-rule-ipset` / `-no-rule-nftset`: 跳过 `ipset` / `nftset` 规则的应用。
        *   `-no-speed-check`: 禁用对解析结果的测速。
        *   `-no-cache`: 禁用 DNS 缓存查找和存储。
        *   `-no-rule-soa`: 跳过返回 SOA 的 `address /domain/#` 规则。
        *   `-no-dualstack-selection`: 禁用双栈 IP 优选逻辑。
        *   `-no-ip-alias`: 忽略 IP 别名规则。
        *   `-force-aaaa-soa`: 强制 AAAA 查询返回 SOA (如果无 AAAA 记录)。
        *   `-force-https-soa`: 强制 HTTPS (SVCB) 查询返回 SOA (如果无 HTTPS 记录)。
        *   `-no-serve-expired`: 不提供过期的缓存记录。
        *   `-no-rules`: 跳过所有域名规则（`address`, `nameserver`, `ipset`, `nftset`, `domain-rules`等）。
        *   `-ipset <ipsetname[,#4:v4set,#6:v6set]>`: 将通过此监听端口成功解析的 IP 地址（默认全部，或指定 IPv4/IPv6）添加到指定的 ipset 集合中。这会覆盖全局或域名特定的 ipset 设置。
        *   `-nftset <#4:fam#tbl#set4,#6:fam#tbl#set6>`: 类似 `-ipset`，但用于 nftables set。
    *   **TLS/HTTPS 特定参数 (全局或在 `bind-tls`/`bind-https` 块内)**:
        *   `bind-cert-key-file <path>`: TLS 私钥文件路径 (PEM 格式)。
        *   `bind-cert-file <path>`: TLS 证书文件路径 (PEM 格式，通常包含完整证书链)。
        *   `bind-cert-key-pass <password>`: TLS 私钥的密码 (如果已加密)。
    *   **示例**：
        ```
        bind :53
        bind [::]:53
        bind 192.168.1.1:5353 -group trusted_clients -no-speed-check
        bind-tcp :53
        bind-tls :853
        bind-cert-file /etc/smartdns/certs/server.crt
        bind-cert-key-file /etc/smartdns/certs/server.key
        ```

*   **`tcp-idle-time <seconds>`**
    *   **描述**：设置 TCP 连接（包括 DoT, DoH）的最大空闲超时时间。如果一个 TCP 连接在此时间内没有任何活动，将被关闭。
    *   **参数**：`<seconds>` - 超时时间，单位为秒。
    *   **默认值**：通常为 60 或 120 秒。
    *   **示例**：`tcp-idle-time 90`

#### 2.2 缓存配置

控制 SmartDNS 的查询结果缓存行为。

*   **`cache-size <number>`**
    *   **描述**：设置 DNS 缓存中可以存储的最大条目数量。
    *   **参数**：
        *   `<number>`: 缓存条目数。
        *   `0`: 禁用缓存。
        *   `-1`: 自动根据内存调整 (具体逻辑依赖实现)。
    *   **默认值**：例如 `32768`。
    *   **示例**：`cache-size 65536`

*   **`cache-mem-size <size>[k|m|g]`**
    *   **描述**：设置 DNS 缓存可以使用的最大物理内存量。当达到此限制时，可能会触发旧缓存条目的淘汰。
    *   **参数**：`<size>` 后可跟 `k` (KB), `m` (MB), `g` (GB)。
    *   **默认值**：无明确限制或根据 `cache-size` 估算。
    *   **示例**：`cache-mem-size 128m`

*   **`cache-persist [yes|no]`**
    *   **描述**：是否在 SmartDNS 重启时持久化缓存内容。如果为 `yes`，缓存会在退出时保存到文件，并在启动时加载。
    *   **默认值**：`no`。
    *   **示例**：`cache-persist yes`

*   **`cache-file <file_path>`**
    *   **描述**：当 `cache-persist yes` 时，指定缓存持久化文件的路径。
    *   **参数**：`<file_path>`。
    *   **默认值**：例如 `/tmp/smartdns.cache` 或 `/var/cache/smartdns/smartdns.cache`。
    *   **示例**：`cache-file /opt/smartdns/cache/smartdns.cache`

*   **`cache-checkpoint-time <seconds>`**
    *   **描述**：当 `cache-persist yes` 时，SmartDNS 会定期将内存中的缓存数据写入到持久化文件。此配置项设置写入操作的时间间隔。
    *   **参数**：`<seconds>` - 时间间隔，单位为秒。
    *   **默认值**：例如 `86400` (一天)。
    *   **示例**：`cache-checkpoint-time 3600` (一小时)

*   **`prefetch-domain [yes|no]`**
    *   **描述**：是否启用域名预取功能。当缓存中的某个域名记录即将过期或被频繁访问时，SmartDNS 会主动向上游服务器查询该域名以更新缓存，保持其新鲜度，从而减少下次查询该域名时的延迟。
    *   **默认值**：`yes`。
    *   **示例**：`prefetch-domain yes`

*   **`serve-expired [yes|no]`**
    *   **描述**：当 DNS 查询命中了一条已过期的缓存记录时，是否仍然使用这条过期数据来响应客户端。如果设置为 `yes`，可以减少在某些网络环境下等待上游响应的时间，但可能会返回不再准确的 IP。通常会配合预取功能在后台更新这条过期记录。
    *   **默认值**：`yes`。
    *   **示例**：`serve-expired yes`

*   **`serve-expired-ttl <seconds>`**
    *   **描述**：当 `serve-expired yes` 且 SmartDNS 决定使用一条过期缓存响应时，此配置项指定了该过期响应中 IP 地址的 TTL 值。这个 TTL 通常较短，以促使客户端尽快重新查询。如果设置为 `0`，则可能使用原始过期记录的 TTL 或一个非常小的值。
    *   **默认值**：`0`。
    *   **示例**：`serve-expired-ttl 60`

*   **`serve-expired-reply-ttl <seconds>`**
    *   **描述**：(此项与 `serve-expired-ttl` 功能可能重叠或为其别名，具体行为需参照实现细节)。通常指当返回过期数据时，在DNS响应中设置的TTL值。
    *   **默认值**：`30`。
    *   **示例**：`serve-expired-reply-ttl 30`

#### 2.3 IP 地址过滤与别名

这些配置用于过滤上游返回的 IP 地址或对特定 IP 进行特殊处理。

*   **`bogus-nxdomain <ip/subnet>`**
    *   **描述**：定义一个或多个 IP 地址或子网。如果上游 DNS 服务器返回的 A/AAAA 记录的 IP 地址属于这里定义的任何一个 `ip/subnet`，SmartDNS 会将此结果视为一个伪造的 NXDOMAIN (域名不存在) 响应，并可能丢弃该结果或尝试从其他上游获取。这常用于屏蔽运营商的广告推送或 DNS 劫持行为。可以配置多条。
    *   **参数**：`<ip/subnet>` - IP 地址 (如 `1.2.3.4`) 或 CIDR 子网 (如 `1.2.3.0/24`)。
    *   **示例**：
        ```
        bogus-nxdomain 127.0.0.1
        bogus-nxdomain 0.0.0.0
        bogus-nxdomain 10.0.0.0/8
        ```

*   **`blacklist-ip <ip/subnet>`**
    *   **描述**：定义一个 IP 黑名单。任何解析到的 IP 地址如果位于此黑名单中，将被丢弃。可以配置多条。
    *   **参数**：`<ip/subnet>`。
    *   **示例**：`blacklist-ip 203.0.113.45`

*   **`whitelist-ip <ip/subnet>`**
    *   **描述**：定义一个 IP 白名单。如果一个上游服务器配置了 `-whitelist-ip` 选项，或者全局设置了白名单，那么只有解析结果中的 IP 位于此白名单中才会被接受。可以配置多条。
    *   **参数**：`<ip/subnet>`。
    *   **示例**：`whitelist-ip 198.51.100.0/24`

*   **`ignore-ip <ip/subnet>`**
    *   **描述**：定义需要忽略的 IP 地址。这些 IP 地址在解析结果中会被直接丢弃，不参与测速和选择。可以配置多条。
    *   **参数**：`<ip/subnet>`。
    *   **示例**：`ignore-ip 224.0.0.1` (一个多播地址)

*   **`ip-alias <ip/subnet_pattern> <target_ip1[,target_ip2]...>`**
    *   **描述**：IP 地址别名。如果解析结果中的某个 IP 地址匹配 `<ip/subnet_pattern>`，SmartDNS 会将其替换为指定的 `<target_ip>` 列表中的一个或多个 IP 地址。这可以用于将内网 IP 映射到公网 IP，或反之，或者将不可路由的 IP 替换为可用的等价 IP。
    *   **参数**：
        *   `<ip/subnet_pattern>`: 要匹配的源 IP 地址或子网。
        *   `<target_ip1[,target_ip2]...>`: 替换后的一个或多个目标 IP 地址。
    *   **示例**：`ip-alias 192.168.1.100 10.0.0.5`

#### 2.4 测速与优化

配置 DNS 解析结果的测速方式和 IP 选择策略。

*   **`speed-check-mode <mode1[,mode2,...]>`**
    *   **描述**：定义对上游服务器返回的 IP 地址进行存活和速度测试的模式。可以指定多种模式，SmartDNS 会尝试这些模式。
    *   **参数**：`<mode>` 可以是：
        *   `ping`: 使用 ICMP ECHO 请求进行 PING 测试。
        *   `tcp:<port>`: 尝试与 IP 地址的指定 TCP 端口建立连接。例如 `tcp:80` (HTTP), `tcp:443` (HTTPS)。
        *   `none`: 不进行任何主动测速。
    *   **默认值**：可能是 `ping` 或 `ping,tcp:80,tcp:443`。
    *   **示例**：
        ```
        speed-check-mode ping,tcp:80,tcp:443
        speed-check-mode tcp:443  // 只测试 HTTPS 端口
        speed-check-mode none    // 完全关闭测速，依赖响应顺序或特定选择模式
        ```

*   **`force-aaaa-soa [yes|no]`**
    *   **描述**：当一个域名没有 AAAA 记录（IPv6 地址）时，是否强制返回一个 SOA 记录（表示权威服务器信息，通常客户端会将其解释为 NXDOMAIN 或类似否定应答）而不是简单地不包含 AAAA 记录。这可以防止某些客户端因缺少 AAAA 记录而不断重试。
    *   **默认值**：`no`。
    *   **示例**：`force-aaaa-soa yes`

*   **`force-qtype-soa [qtype_id | start_id-end_id | ...]`**
*   **`force-qtype-soa [-,][qtype_id | start_id-end_id | ...]`**
    *   **描述**：强制特定 DNS 查询类型 (QTYPE) 在没有对应记录时返回 SOA。
    *   **参数**：
        *   `qtype_id`: DNS 查询类型的数字 ID (例如 A 是 1, AAAA 是 28, HTTPS 是 65)。
        *   `start_id-end_id`: 一个范围内的 QTYPE ID。
        *   使用逗号分隔多个类型或范围。
        *   前缀 `-` 表示从已设置的列表中移除指定的 QTYPE。单独一个 `-` 表示清除所有已设置的强制 SOA 类型。
    *   **示例**：
        ```
        force-qtype-soa 65          // HTTPS (SVCB) 查询无结果时返回 SOA
        force-qtype-soa 250-255   // QTYPE 250 到 255 查询无结果时返回 SOA
        force-qtype-soa -,65        // 取消对 HTTPS 查询的强制 SOA
        ```

*   **`dualstack-ip-selection [yes|no]`**
    *   **描述**：是否启用 IPv4/IPv6 双栈 IP 地址选择优化。当一个域名同时拥有 A 和 AAAA 记录时，此功能会尝试选择网络质量更好（例如延迟更低）的 IP 地址类型返回给客户端，或者根据一定的偏好对两者进行排序。
    *   **默认值**：`no` (或者可能是 `yes`，具体取决于 SmartDNS 版本和编译选项)。
    *   **示例**：`dualstack-ip-selection yes`

*   **`dualstack-ip-selection-threshold <milliseconds>`**
    *   **描述**：当 `dualstack-ip-selection yes` 时，此阈值用于比较 IPv4 和 IPv6 地址的测速延迟。如果 IPv6 的延迟比 IPv4 的延迟低超过这个阈值，可能会优先选择 IPv6，反之亦然。具体比较逻辑可能更复杂。
    *   **参数**：`<milliseconds>` - 延迟差异阈值，单位毫秒。
    *   **默认值**：例如 `0` 或 `20`。
    *   **示例**：`dualstack-ip-selection-threshold 50`

*   **`dualstack-ip-allow-force-aaaa [yes|no]`**
    *   **描述**：(此选项的确切含义需结合代码分析) 可能指在双栈选择过程中，即使 AAAA 记录的测速结果不佳，是否仍然允许在某些条件下（例如没有好的 A 记录）强制选择或包含 AAAA 记录。
    *   **默认值**：`yes` 或 `no`。
    *   **示例**：`dualstack-ip-allow-force-aaaa yes`


#### 2.5 EDNS 和 TTL 配置

这些配置涉及 EDNS (Extension Mechanisms for DNS) 客户端子网选项和资源记录的生存时间 (TTL)。

*   **`edns-client-subnet <ip/subnet>`**
    *   **描述**：配置 EDNS0 Client Subnet (ECS) 选项。如果设置了此项，SmartDNS 在向上游 DNS 服务器（支持 ECS 的服务器）发送查询时，会附加指定的 `<ip/subnet>` 信息。这使得上游服务器能够根据客户端的地理位置（或指定的子网位置）返回更具地理针对性的 DNS 解析结果。可以配置 IPv4 和 IPv6 子网。
    *   **参数**：`<ip/subnet>` - 要在 EDNS 请求中发送的客户端源 IP 地址或子网。例如 `1.2.3.0/24` 或 `2001:db8::/56`。如果只提供 IP，通常会使用该 IP 的 /24 (IPv4) 或 /56 (IPv6) 作为子网。
    *   **默认值**：不发送 ECS 信息。
    *   **示例**：
        ```
        edns-client-subnet 192.0.2.10/24
        edns-client-subnet 2001:db8:1234::/48
        ```

*   **`rr-ttl <seconds>`**
    *   **描述**：为所有 SmartDNS 自己生成的或权威应答中的资源记录设置一个固定的 TTL 值。这会覆盖从上游获取的或规则中定义的 TTL，除非被 `rr-ttl-min` 和 `rr-ttl-max` 限制。
    *   **参数**：`<seconds>` - TTL 值。
    *   **默认值**：不设置，使用原始 TTL。
    *   **示例**：`rr-ttl 300` (所有记录 TTL 为 5 分钟)

*   **`rr-ttl-min <seconds>`**
    *   **描述**：设置 SmartDNS 返回给客户端的资源记录的最小 TTL 值。即使上游返回的 TTL 或计算出的 TTL 小于此值，SmartDNS 也会将其提升到 `<seconds>`。
    *   **参数**：`<seconds>`。
    *   **默认值**：例如 `0` 或 `60`。
    *   **示例**：`rr-ttl-min 120` (最小 TTL 为 2 分钟)

*   **`rr-ttl-max <seconds>`**
    *   **描述**：设置 SmartDNS 返回给客户端的资源记录的最大 TTL 值。即使上游返回的 TTL 或计算出的 TTL 大于此值，SmartDNS 也会将其限制在 `<seconds>`。
    *   **参数**：`<seconds>`。
    *   **默认值**：例如 `86400` (一天)。
    *   **示例**：`rr-ttl-max 3600` (最大 TTL 为 1 小时)

*   **`rr-ttl-reply-max <seconds>`**
    *   **描述**：(此选项与 `rr-ttl-max` 功能可能相似或有细微差别，需代码确认)。通常指在实际回复给客户端的 DNS 报文中，资源记录的 TTL 不会超过此值。
    *   **默认值**：例如 `600`。
    *   **示例**：`rr-ttl-reply-max 300`

#### 2.6 限制与响应模式

控制 DNS 查询的速率限制和 SmartDNS 选择最终 IP 的行为模式。

*   **`max-reply-ip-num <number>`**
    *   **描述**：设置在 DNS 响应中返回给客户端的最大 IP 地址数量。即使 SmartDNS 解析到更多符合条件的 IP 地址，也只会选择最优的 `<number>` 个返回。
    *   **参数**：`<number>` - 通常为 1 到 16 之间。
    *   **默认值**：`1` 或 `8`。
    *   **示例**：`max-reply-ip-num 2`

*   **`max-query-limit <number>`**
    *   **描述**：设置 SmartDNS 每秒可以处理的最大 DNS 查询请求数量。设置为 `0` 表示没有限制。这是一个基本的防滥用机制。
    *   **参数**：`<number>`。
    *   **默认值**：`0` (无限制)。
    *   **示例**：`max-query-limit 1000`

*   **`response-mode <mode>`**
    *   **描述**：定义 SmartDNS 在从多个上游服务器获得多个 IP 地址并进行测速后，如何选择最终返回给客户端的 IP 地址的策略。
    *   **参数**：`<mode>` 可以是：
        *   `first-ping`: 选择并发查询中第一个能够被 PING 通的 IP 地址。不一定是最快的，但保证基本可用。
        *   `fastest-ip`: 选择所有并发查询结果中，经过测速后延迟最低的 IP 地址。
        *   `fastest-response`: 不等待所有并发查询或完整测速，而是当第一个上游服务器返回有效结果时，如果该结果通过了基本的规则检查（如黑白名单），就立即使用这个结果响应客户端。后续的查询结果和测速数据主要用于更新缓存和统计信息。
    *   **默认值**：可能是 `fastest-ip`。
    *   **示例**：`response-mode fastest-response`

#### 2.7 日志与审计

配置 SmartDNS 的日志记录和审计功能。

*   **`log-level <level>`**
    *   **描述**：设置日志输出的详细级别。
    *   **参数**：`<level>` 可以是 `off`, `fatal`, `error`, `warn`, `notice`, `info`, `debug`。级别越低，日志越详细 (`debug` 最详细)。
    *   **默认值**：`info`。
    *   **示例**：`log-level notice`

*   **`log-file <file_path>`**
    *   **描述**：指定日志文件的路径。如果未配置，日志可能输出到控制台或 syslog。
    *   **参数**：`<file_path>`。
    *   **默认值**：无，或如 `/var/log/smartdns/smartdns.log`。
    *   **示例**：`log-file /tmp/smartdns.log`

*   **`log-size <size>[k|m|g]`**
    *   **描述**：设置单个日志文件的最大大小。当达到此大小时，会进行日志轮转（如果 `log-num` > 1）。
    *   **参数**：`<size>` 后可跟 `k`, `m`, `g`。
    *   **默认值**：例如 `128k`。
    *   **示例**：`log-size 10m`

*   **`log-num <number>`**
    *   **描述**：设置保留的轮转日志文件的数量。当主日志文件达到 `log-size` 时，会重命名为 `log-file.1`，新的日志写入 `log-file`。如果 `log-num` 为 2，则会保留 `log-file.0` (即当前日志) 和 `log-file.1`。设置为 `0` 或 `1` 通常表示不进行或只保留一个文件（无轮转）。
    *   **参数**：`<number>`。
    *   **默认值**：`1` 或 `2`。
    *   **示例**：`log-num 5`

*   **`log-console [yes|no]`**
    *   **描述**：是否将日志信息输出到标准控制台 (stdout/stderr)。当 SmartDNS 在前台运行时此选项比较有用。
    *   **默认值**：`no` (当作为守护进程运行时)。
    *   **示例**：`log-console yes`

*   **`log-syslog [yes|no]`**
    *   **描述**：是否将日志信息发送到系统的 syslog 服务。
    *   **默认值**：`yes` (在某些系统上)。
    *   **示例**：`log-syslog yes`

*   **`log-file-mode <mode>`**
    *   **描述**：设置日志文件的权限模式 (八进制表示)。
    *   **参数**：`<mode>`，如 `644`, `600`。
    *   **默认值**：系统默认。
    *   **示例**：`log-file-mode 640`

*   **`audit-enable [yes|no]`**
    *   **描述**：是否启用 DNS 查询审计功能。审计日志通常记录每个 DNS 查询的详细信息，如时间、客户端 IP、查询域名、类型、返回的 IP、使用的上游服务器等。
    *   **默认值**：`no`。
    *   **示例**：`audit-enable yes`

*   **`audit-SOA [yes|no]`**
    *   **描述**：当 `audit-enable yes` 时，是否在审计日志中记录那些结果为 SOA 的查询。
    *   **默认值**：`no` 或 `yes`。
    *   **示例**：`audit-SOA no`

*   **`audit-file <file_path>`**
    *   **描述**：指定审计日志文件的路径。
    *   **参数**：`<file_path>`。
    *   **默认值**：例如 `/var/log/smartdns-audit.log`。
    *   **示例**：`audit-file /opt/smartdns/audit.log`

*   **`audit-size`, `audit-num`, `audit-console`, `audit-syslog`, `audit-file-mode`**
    *   **描述**：这些选项与对应的 `log-*` 选项功能类似，但应用于审计日志。

#### 2.8 集成与其他

主要涉及与其他服务（如 dnsmasq）的集成或 TLS 相关的全局设置。

*   **`dnsmasq-lease-file <file_path>`**
    *   **描述**：指定 dnsmasq 服务生成的 DHCP 租约文件路径。SmartDNS 可以读取此文件，从而能够解析本地网络中通过 DHCP 获取 IP 的主机名。
    *   **参数**：`<file_path>`。
    *   **默认值**：通常是 `/var/lib/misc/dnsmasq.leases` 或 `/tmp/dnsmasq.leases`。
    *   **示例**：`dnsmasq-lease-file /var/lib/dnsmasq/dnsmasq.leases`

*   **`ca-file <file_path>`**
    *   **描述**：指定一个包含受信任 CA 证书的 PEM 文件。此文件用于验证上游 DoT/DoH/DoQ 服务器证书的有效性。
    *   **参数**：`<file_path>`。
    *   **默认值**：系统 CA 证书包，如 `/etc/ssl/certs/ca-certificates.crt`。
    *   **示例**：`ca-file /etc/custom_cas.pem`

*   **`ca-path <directory_path>`**
    *   **描述**：指定一个包含多个受信任 CA 证书文件（特定命名格式，如哈希值.0）的目录。用于验证上游服务器证书。
    *   **参数**：`<directory_path>`。
    *   **默认值**：系统 CA 证书目录，如 `/etc/ssl/certs`。
    *   **示例**：`ca-path /etc/ssl/custom_certs/`

#### 2.9 上游 DNS 服务器配置

定义 SmartDNS 将查询请求转发到的外部 DNS 服务器。这是 SmartDNS 的核心配置部分。

*   **`server <IP_address_or_URL:[port]> [options...]`** (用于 UDP, 也可自动识别协议)
*   **`server-tcp <IP_address:[port]> [options...]`**
*   **`server-tls <host_or_IP:[port]> [options...]`** (DoT, 默认端口 853)
*   **`server-https <URL> [options...]`** (DoH, 默认端口 443, URL 如 `https://dns.google/dns-query`)
*   **`server-quic <host_or_IP:[port]> [options...]`** (DoQ, 默认端口 853 或 784)
*   **`server-h3 <URL> [options...]`** / **`server-http3 <URL> [options...]`** (DoH3, 默认端口 443)
    *   **描述**：配置一个上游 DNS 服务器。可以添加多个不同协议和不同地址的服务器。
    *   **参数 (基本)**：
        *   `IP_address_or_URL:[port]`: 服务器的 IP 地址或主机名 (对于 DoT/DoH/DoQ/DoH3)。对于 DoH/DoH3，通常是一个完整的 URL。端口可选，如果省略则使用协议的默认端口。
    *   **`options` (可为每个上游服务器单独设置)**:
        *   `-group <group_name1> [-group <group_name2> ...]`：将此服务器分配到一个或多个服务器组。域名规则中的 `nameserver /domain/group_name` 可以指定使用哪个组。
        *   `-exclude-default-group`: 此服务器不属于默认服务器组（即没有被 `-group` 指定的服务器自动构成的组）。
        *   `-blacklist-ip`: 使用全局定义的 `blacklist-ip` 列表过滤此服务器返回的结果。
        *   `-whitelist-ip`: 使用全局定义的 `whitelist-ip` 列表过滤此服务器返回的结果（即只有在白名单中的 IP 才会被接受）。
        *   `-check-edns`: 要求此服务器返回的响应必须包含 EDNS0 记录，否则丢弃结果。
        *   `-proxy <proxy_name>`: 通过名为 `<proxy_name>` 的已配置代理服务器（见 `proxy-server` 指令）连接此上游服务器。
        *   `-bootstrap-dns`: 将此服务器标记为引导 DNS 服务器。引导服务器用于解析其他 DoT/DoH/DoQ/DoH3 服务器的主机名。引导服务器自身通常应配置为 IP 地址或通过不需要进一步解析的连接方式。
        *   `-set-mark <mark_value>`: (Linux 特定) 在发往此服务器的查询报文上设置一个 netfilter 标记 (fwmark)。
        *   `-subnet <ip/subnet>`: 为发往此特定服务器的查询附加 EDNS Client Subnet 信息，覆盖全局 `edns-client-subnet` 设置。
        *   `-host-ip <ip_address>`: 当上游服务器地址是域名时，可以指定一个固定的 IP 地址用于连接，而不是动态解析该域名。
        *   `-interface <if_name>`: 通过指定的网络接口发送到此服务器的查询。
        *   `-fallback`: 将此服务器标记为备用服务器。可能在常规服务器查询失败或超时后才使用。
        *   **TLS/QUIC/HTTPS 特定选项**:
            *   `-spki-pin <sha256_pin>`: 指定一个或多个 Base64 编码的 SHA256 SPKI (Subject Public Key Info) Pin。用于验证服务器证书的公钥，增强安全性，防止中间人攻击。
            *   `-tls-host-verify <hostname>`: 指定在 TLS 握手时要验证的服务器证书中的主机名。通常应与连接的服务器主机名一致。
            *   `-host-name <sni_hostname>`: 指定在 TLS ClientHello 中发送的 SNI (Server Name Indication) 主机名。这对于连接到在同一 IP 上托管多个安全域名的服务器非常重要。
            *   `-http-host <http_host_header>` (DoH/DoH3 特定): 指定 HTTP Host 请求头的值。
            *   `-k` / `-no-check-certificate`: 禁用对此服务器的 TLS 证书验证（**不推荐，会降低安全性**）。
            *   `-alpn <protocol_name>` (DoH3/DoQ特定): 指定 ALPN (Application-Layer Protocol Negotiation) 协议名称，如 `h3` for DoH3, `doq` for DoQ。
    *   **示例**：
        ```
        server 8.8.8.8 -group google_dns
        server-tcp 1.1.1.1:53
        server-tls dns.quad9.net -spki-pin "pin1base64==" -spki-pin "pin2base64=="
        server-https https://cloudflare-dns.com/dns-query -host-name cloudflare-dns.com
        server-quic quic.adguard-dns.com:784 -alpn doq
        server 223.5.5.5 -proxy my_socks_proxy -group alidns
        ```

*   **`proxy-server <URL> -name <proxy_name>`**
    *   **描述**：定义一个代理服务器，可供上游 DNS 服务器通过 `-proxy <proxy_name>` 选项使用。
    *   **参数**：
        *   `<URL>`: 代理服务器的 URL，格式为：
            *   SOCKS5: `socks5://[username:password@]host:port`
            *   HTTP: `http://[username:password@]host:port`
        *   `-name <proxy_name>`: 为此代理配置指定一个唯一的名称。
    *   **示例**：
        ```
        proxy-server socks5://user1:pass1@10.0.0.1:1080 -name proxy_socks
        proxy-server http://10.0.0.2:3128 -name proxy_http
        ```

#### 2.10 域名级规则 (Domain-Specific Rules)

这些指令允许针对特定的域名或域名模式进行精细化的控制。

*   **`nameserver /<domain_pattern>/[<group_name>|-]`**
    *   **描述**：为匹配 `<domain_pattern>` 的域名查询指定使用名为 `<group_name>` 的上游服务器组。如果使用 `-` 作为组名，则表示忽略对此域名的常规上游查询（其效果可能类似于 `address /<domain_pattern>/#`，即返回 SOA 或不解析，具体行为取决于实现，通常意味着不由 SmartDNS 解析，而是依赖于其他机制或返回否定答案）。
    *   **参数**：
        *   `/<domain_pattern>/`: 域名模式。可以是：
            *   精确域名：如 `/www.example.com/`
            *   通配符域名：如 `/*.example.com/` (匹配 `example.com` 的所有一级子域名)
            *   仅根域名：如 `/-.example.com/` (仅匹配 `example.com` 本身，不匹配子域名)
            *   `domain-set` 引用：如 `/domain-set:myset/` (匹配 `myset` 域名集合中的所有域名)
        *   `<group_name>`: 已定义的上游服务器组名。
        *   `-`: 特殊标记，表示不通过常规上游服务器解析此域名。
    *   **示例**：
        ```
        nameserver /google.com/google_dns_group
        nameserver /apple.com/us_dns_group
        nameserver /domain-set:streaming_services/fast_dns_group
        nameserver /annoying.tracker.com/-
        ```

*   **`address /<domain_pattern>/[<ip1[,ip2,...]>|-|#|-4|-6|#4|#6]`**
    *   **描述**：为匹配 `<domain_pattern>` 的域名查询直接指定返回的 IP 地址，或进行特殊处理。
    *   **参数**：
        *   `/<domain_pattern>/`: 域名模式，同 `nameserver` 指令。
        *   `<ip1[,ip2,...]>`: 一个或多个 IPv4 或 IPv6 地址。客户端将收到这些地址。
        *   `-`: 表示此域名不由 SmartDNS 直接应答静态 IP，而是向上游服务器查询（如果前面没有 `nameserver` 规则指定特定组，则使用默认组）。这是默认行为，但可用于覆盖更广泛规则的静态地址部分。
        *   `#`: 返回一个 SOA 记录，通常客户端会将其视为空结果或域名不存在 (NXDOMAIN)。常用于屏蔽域名。
        *   `-4`: 仅向上游查询 AAAA 记录 (IPv6)，不查询 A 记录 (IPv4)。如果 AAAA 不存在，行为取决于 `force-aaaa-soa`。
        *   `-6`: 仅向上游查询 A 记录 (IPv4)，不查询 AAAA 记录 (IPv6)。
        *   `#4`: 屏蔽此域名的 A 记录查询 (返回 SOA)，AAAA 查询正常。
        *   `#6`: 屏蔽此域名的 AAAA 记录查询 (返回 SOA)，A 查询正常。
    *   **示例**：
        ```
        address /my.local.server/192.168.1.100
        address /ads.example.com/#
        address /ipv6.only.example.com/-4
        address /domain-set:blocked_sites/#
        ```

*   **`cname /<domain_pattern>/<target_domain>`**
    *   **描述**：为匹配 `<domain_pattern>` 的域名查询返回一个 CNAME (Canonical Name) 记录，指向 `<target_domain>`。客户端会随后对 `<target_domain>`发起新的 DNS 查询。
    *   **参数**：
        *   `/<domain_pattern>/`: 源域名模式。
        *   `<target_domain>`: CNAME 指向的目标域名。
    *   **示例**：`cname /alias.example.com/real.service.example.net`

*   **`srv-record /<service_domain_pattern>/[<target>][,<port>][,<priority>][,<weight>]`**
    *   **描述**：为匹配 `<service_domain_pattern>` (通常格式为 `_service._proto.name`) 的 SRV 查询配置 SRV 记录。
    *   **参数**：
        *   `/<service_domain_pattern>/`: SRV 服务域名模式。
        *   `<target>`: 提供服务的主机名。
        *   `<port>`: 服务端口号。
        *   `<priority>`: 记录优先级 (0-65535，越小越优先)。
        *   `<weight>`:相同优先级记录的权重 (0-65535，用于负载均衡)。
        *   如果只提供服务域名，如 `srv-record /_ldap._tcp.example.com/`，则表示对该 SRV 查询返回 NXDOMAIN 或空结果（具体取决于实现），有效地阻止解析。
    *   **示例**：
        ```
        srv-record /_ldap._tcp.example.com/ldap-server.example.com,389,10,100
        srv-record /_sip._udp.example.com/sip-proxy.example.com,5060
        ```

*   **`https-record /<domain_pattern>/[target=...][,port=...][,priority=...][,alpn=...][,ech=...][,ipv4hint=...][,ipv6hint=...]`**
    *   **描述**：为匹配 `<domain_pattern>` 的 HTTPS (类型 65，也称 SVCB) 查询配置 HTTPS 记录。
    *   **参数**：键值对形式，逗号分隔。
        *   `target`: 服务目标主机名 (默认为源域名)。
        *   `port`: 服务端口 (默认为 443)。
        *   `priority`: 记录优先级 (0-65535，越小越优先，`0` 表示 AliasMode)。
        *   `alpn`: 应用层协议协商 ID 列表 (如 `h2,h3`)。
        *   `ech`: Encrypted Client Hello 配置。
        *   `ipv4hint`: IPv4 地址提示。
        *   `ipv6hint`: IPv6 地址提示。
        *   `noipv4hint`, `noipv6hint`: 特殊标记，表示不提供 IP 地址提示。
    *   **示例**：
        ```
        https-record /www.example.com/priority=1,target=svc.example.net,alpn=h2,ipv4hint=192.0.2.1
        https-record /cdn.example.com/noipv4hint,noipv6hint // 表示此 HTTPS 记录仅用于服务参数，不提供 IP 解析提示
        ```

#### 2.11 DNS64 配置

用于 IPv6 过渡技术。

*   **`dns64 <nat64_prefix/length>`**
    *   **描述**：启用 DNS64 功能，并将指定的 NAT64 前缀用于合成 AAAA 记录。当客户端仅有 IPv6 连接，但请求的域名只有 IPv4 地址 (A 记录) 时，DNS64 服务器会将 A 记录的 IPv4 地址嵌入到 `<nat64_prefix>` 中，合成为一个 AAAA 记录返回给客户端。
    *   **参数**：`<nat64_prefix/length>` - NAT64 IPv6 前缀及其长度，例如 `64:ff9b::/96` (这是标准的 Well-Known Prefix)。
    *   **默认值**：禁用。
    *   **示例**：`dns64 64:ff9b::/96`

#### 2.12 ipset 和 nftset 集成

将域名解析结果动态添加到 Linux 内核的 ipset 或 nftables set 中，常用于防火墙规则联动。

*   **`ipset-timeout [yes|no]`**
    *   **描述**：当 IP 地址被添加到 ipset 时，是否根据 DNS 记录的 TTL 自动设置 ipset 条目的超时时间。如果为 `yes`，当 TTL 到期后，ipset 条目也可能自动移除。
    *   **默认值**：`no` (或 `yes`，取决于版本)。
    *   **示例**：`ipset-timeout yes`

*   **`ipset /<domain_pattern>/[<ipset_name_v4_v6>|#4:<v4_setname>|#6:<v6_setname>|-|#4:-|#6:-]`**
*   **`ipset [<ipset_name_v4_v6>|#4:<v4_setname>|#6:<v6_setname>]`** (全局 ipset)
    *   **描述**：将匹配 `<domain_pattern>` 的域名解析到的 IP 地址添加到一个或多个 ipset 集合中。
    *   **参数**：
        *   `/<domain_pattern>/`: 域名模式，或省略表示全局（所有解析结果）。
        *   `<ipset_name_v4_v6>`: 一个 ipset 名称，IPv4 和 IPv6 地址都会添加到此集合。
        *   `#4:<v4_setname>`: 仅将 IPv4 地址添加到名为 `<v4_setname>` 的 ipset。
        *   `#6:<v6_setname>`: 仅将 IPv6 地址添加到名为 `<v6_setname>` 的 ipset。
        *   `-`: 对于此域名模式，禁用 ipset 添加 (即使有全局 ipset 配置)。
        *   `#4:-` / `#6:-`: 分别禁用 IPv4/IPv6 地址的 ipset 添加。
        *   可以组合使用 `#4:` 和 `#6:` 来为不同地址族指定不同集合，例如 `ipset /example.com/#4:v4_example,#6:v6_example`。
    *   **示例**：
        ```
        ipset /gfw.list.example.com/gfwlist_ipset
        ipset /video.example.com/#4:video_v4_ipset,#6:video_v6_ipset
        ipset global_v4_traffic_set # 全局，只对v4
        ipset /no.ipset.example.com/-
        ```

*   **`ipset-no-speed <ipsetname>`**
    *   **描述**：当一个 IP 地址因为测速失败（例如 PING 不通或 TCP 连接超时）而被 SmartDNS 判定为不可用时，如果配置了此项，该“坏”IP 仍会被添加到一个名为 `<ipsetname>` 的特殊 ipset 集合中。这可以用于将这些不良 IP 反馈给防火墙进行特殊处理（例如，阻止它们或记录它们）。
    *   **参数**：`<ipsetname>`。
    *   **示例**：`ipset-no-speed bad_ips_set`

*   **`nftset-timeout [yes|no]`**
    *   **描述**：类似 `ipset-timeout`，但用于 nftables set。
    *   **默认值**：`yes`。
    *   **示例**：`nftset-timeout yes`

*   **`nftset /<domain_pattern>/[#4:<family>#<table>#<set4>,#6:<family>#<table>#<set6>]`**
*   **`nftset [#4:<family>#<table>#<set4>,#6:<family>#<table>#<set6>]`** (全局 nftset)
    *   **描述**：将匹配 `<domain_pattern>` 的域名解析到的 IP 地址添加到 nftables set 中。
    *   **参数**：
        *   `/<domain_pattern>/`: 域名模式，或省略表示全局。
        *   `#4:<family>#<table>#<set4>`: 将 IPv4 地址添加到指定的 nftables set。`<family>` (如 `ip`, `arp`, `inet`), `<table>` (表名), `<set4>` (set 名称)。
        *   `#6:<family>#<table>#<set6>`: 将 IPv6 地址添加到指定的 nftables set。
        *   同样支持 `-` 和 `#4:-`, `#6:-` 来禁用。
    *   **示例**：
        ```
        nftset /streaming.example.com/#4:ip#filter_table#video_v4_set,#6:ip6#filter_table#video_v6_set
        nftset #4:inet#fw_table#all_v4_traffic_set // 全局，只对v4
        ```

*   **`nftset-no-speed [#4:<fam>#<tbl>#<set>,#6:<fam>#<tbl>#<setv6>]`**
    *   **描述**：类似 `ipset-no-speed`，但用于将测速失败的 IP 添加到 nftables set。
    *   **示例**：`nftset-no-speed #4:ip#main_table#unreachable_ips`

*   **`nftset-debug [yes|no]`**
    *   **描述**：启用 nftables set 操作的调试日志，有助于排查配置问题。
    *   **默认值**：`no`。
    *   **示例**：`nftset-debug yes`

#### 2.13 动态 DNS (DDNS) 和 mDNS

*   **`ddns-domain <domain>`**
    *   **描述**：(此配置的确切功能和实现方式需要详细查阅源码或更专门的文档)。通常 DDNS (Dynamic DNS) 用于当本地公网 IP 地址变化时，自动更新 DNS 服务商处对应域名的 A/AAAA 记录。SmartDNS 中的此配置项可能：
        1.  标记一个本地管理的域名，SmartDNS 可能会监控其 IP 变化并更新（如果 SmartDNS 自身扮演 DDNS 更新客户端的角色）。
        2.  或者，标记一个需要特殊处理的 DDNS 域名，例如在解析时采用更短的 TTL 或避免缓存。
    *   **参数**：`<domain>` - 要进行 DDNS 处理的域名。
    *   **示例**：`ddns-domain myhome.dyndns.org`

*   **`mdns-lookup [yes|no]`**
    *   **描述**：是否启用 mDNS (Multicast DNS) 查询功能。如果为 `yes`，当 SmartDNS 收到一个对 `.local` 后缀域名或其他本地名称的查询，且在常规解析流程中未找到结果时，它可能会通过发送 mDNS 查询到本地网络来尝试解析该名称。这用于发现和连接本地网络中的设备和服务 (如打印机、NAS)。
    *   **默认值**：`no`。
    *   **示例**：`mdns-lookup yes`

#### 2.14 Hosts 文件

*   **`hosts-file <file_path>`**
    *   **描述**：指定一个或多个自定义的 hosts 文件。SmartDNS 会加载这些文件，并优先使用其中定义的静态 IP-域名映射关系来应答查询，其优先级通常高于上游查询和大部分域名规则 (但可能低于某些强制的 `address /domain/#` 规则)。可以配置多条 `hosts-file` 指令。
    *   **参数**：`<file_path>` - hosts 文件的路径，格式同标准的 `/etc/hosts`。
    *   **示例**：
        ```
        hosts-file /etc/smartdns/custom_hosts
        hosts-file /opt/adblock_hosts_file
        ```

#### 2.15 高级规则 (`domain-rules`, `domain-set`, `ip-rules`, `ip-set`)

这些配置提供了更强大和灵活的规则组合能力。

*   **`domain-rules /<domain_pattern>/ [-option value] ...`**
    *   **描述**：这是一个复合规则指令，允许为匹配 `<domain_pattern>` 的域名一次性设置多个覆盖全局或组配置的特定行为。
    *   **参数**：
        *   `/<domain_pattern>/`: 域名模式，同 `nameserver` 和 `address`。
        *   **`-option value` (可以有多个)**:
            *   `-speed-check-mode <mode1[,mode2,...]>`: 为此域名设置特定的测速模式。
            *   `-address [<ip1,...>|-|#|...]`: 为此域名设置特定的静态 IP 或屏蔽行为。
            *   `-nameserver [<group_name>|-]`: 为此域名指定特定的上游服务器组。
            *   `-ipset [<ipset_config>]`: 为此域名配置 ipset (格式同全局 `ipset` 的参数部分)。
            *   `-nftset [<nftset_config>]`: 为此域名配置 nftset。
            *   `-dualstack-ip-selection [yes|no]`: 为此域名启用/禁用双栈 IP 选择。
            *   `-cname <target_domain>`: 为此域名设置 CNAME。 (虽然也可用独立的 `cname` 指令)
            *   `-https-record <params>`: 为此域名设置 HTTPS 记录。
            *   `-rr-ttl <seconds>`, `-rr-ttl-min <seconds>`, `-rr-ttl-max <seconds>`: 设置 TTL。
            *   `-no-serve-expired`: 不为此域名提供过期缓存。
            *   `-no-cache`: 不为此域名使用缓存。
            *   `-no-ip-alias`: 不为此域名应用 IP 别名。
            *   `-enable-cache`: (如果 `-no-cache` 是更上层规则) 强制为此域名启用缓存。
            *   `-delete`: 删除之前为该 `<domain_pattern>` 定义的所有 `domain-rules`。
            *   `-group <group_name>`: (元选项) 将此条 `domain-rules` 本身归属到一个规则组，用于更复杂的配置管理，较少直接使用。
    *   **示例**：
        ```
        domain-rules /fast.example.com/ -speed-check-mode tcp:443 -nameserver high_speed_dns -no-cache
        domain-rules /local.resource/ -address 192.168.0.10 -rr-ttl 3600
        domain-rules /domain-set:video_sites/ -ipset video_ipset -dualstack-ip-selection no
        ```

*   **`domain-set -name <set_name> -type <list|geosite|geositelist> -file <file_path>`**
    *   **描述**：定义一个名为 `<set_name>` 的域名集合。这个集合可以在其他规则 (如 `address`, `nameserver`, `ipset`, `domain-rules`, `client-rules` 的域名匹配部分) 中通过 `/domain-set:<set_name>/` 的方式引用。
    *   **参数**：
        *   `-name <set_name>`: 域名集合的唯一名称。
        *   `-type <list|geosite|geositelist>`: 集合的类型。
            *   `list`: `<file_path>` 是一个纯文本文件，每行包含一个域名。
            *   `geosite`: `<file_path>` 是一个特定格式的文件（类似简化的 geosite 文件），包含 `full:domain`, `domain:suffix`, `keyword:text`, `regexp:pattern` 这样的条目。SmartDNS 会将 `keyword` 转为包含关键词的正则，`regexp` 直接使用。
            *   `geositelist`: 类似 `geosite`，但会忽略 `keyword:` 和 `regexp:` 类型的条目，主要处理 `full:` 和 `domain:`。
        *   `-file <file_path>`: 包含域名列表或 geosite 数据的文件路径。支持 `glob` 通配符。
    *   **示例**：
        ```
        domain-set -name my_local_domains -type list -file /etc/smartdns/local_domains.txt
        domain-set -name cn_domains -type geosite -file /etc/smartdns/geosite_cn.txt
        domain-set -name ad_block_keywords -type geosite -file /etc/smartdns/ad_keywords.txt
        # 然后在其他地方使用:
        # address /domain-set:ad_block_keywords/#
        # nameserver /domain-set:cn_domains/china_dns_group
        ```

*   **`ip-rules <ip_cidr_pattern> [-option value] ...`**
    *   **描述**：针对匹配 `<ip_cidr_pattern>` 的 IP 地址（通常是上游返回的解析结果）应用特定的过滤或修改规则。
    *   **参数**：
        *   `<ip_cidr_pattern>`: 一个 IP 地址或 CIDR 子网，也可以是 `ip-set` 引用。
        *   **`-option value`**:
            *   `-ip-alias <target_ip1[,target_ip2]...>`: 将匹配的源 IP 替换为此处的 IP (类似全局 `ip-alias`，但作用域更小)。
            *   `-whitelist-ip`: 将匹配的 IP 视为白名单 IP (如果其他地方有白名单检查)。
            *   `-blacklist-ip`: 将匹配的 IP 视为黑名单 IP (会被过滤)。
            *   `-bogus-nxdomain`: 将包含此 IP 的解析结果视为伪造 NXDOMAIN。
            *   `-ignore-ip`: 忽略包含此 IP 的解析结果。
    *   **示例**：
        ```
        ip-rules 192.168.0.0/16 -ignore-ip // 忽略所有来自这个私有网络的解析结果
        ip-rules ip-set:cdn_provider_ips -ip-alias 127.0.0.1 // 将特定CDN提供商的IP替换为环回地址
        ```

*   **`ip-set -name <set_name> -type list -file <file_path>`**
    *   **描述**：定义一个名为 `<set_name>` 的 IP 地址集合。目前 `-type` 仅支持 `list`。此集合可以在 `ip-rules` 或 `client-rules` (用于匹配客户端 IP) 中通过 `ip-set:<set_name>` 引用。
    *   **参数**：
        *   `-name <set_name>`: IP 集合的名称。
        *   `-type list`: 目前仅支持此类型。
        *   `-file <file_path>`: 包含 IP 地址或 CIDR 子网列表的文件，每行一个。
    *   **示例**：
        ```
        ip-set -name blocked_tracker_ips -type list -file /etc/smartdns/tracker_ips.txt
        # 然后在 ip-rules 中使用:
        # ip-rules ip-set:blocked_tracker_ips -blacklist-ip
        ```

#### 2.16 客户端规则 (Client Rules)

允许根据 DNS 请求的来源客户端 (IP 地址, MAC 地址或 IP 地址集合) 应用不同的 DNS 处理策略。

*   **`client-rules <client_specifier> [options...]`**
    *   **描述**：为匹配 `<client_specifier>` 的客户端定义一套独立的 DNS 解析选项，这些选项会覆盖全局或 `bind` 端口的默认设置。
    *   **参数**：
        *   `<client_specifier>`: 客户端标识。可以是：
            *   IP 地址：如 `192.168.1.100`
            *   CIDR 子网：如 `192.168.1.0/24`
            *   MAC 地址：如 `AA:BB:CC:DD:EE:FF` (SmartDNS 需要能获取到客户端 MAC，通常在同一局域网且直接查询时可行)
            *   `ip-set` 引用：如 `ip-set:trusted_clients_ips`
        *   **`[options...]`**: 与 `bind` 指令的 `options` 完全相同。例如：
            *   `-group <group_name>`: 此客户端的查询默认使用 `<group_name>` 服务器组。
            *   `-no-speed-check`, `-no-cache`, `-no-rule-addr`, `-no-rule-nameserver`, `-no-rule-ipset`, `-no-rule-soa`, `-no-dualstack-selection` 等。
    *   **示例**：
        ```
        client-rules 192.168.1.50 -group kids_dns_group -no-cache // 孩子设备使用特定DNS组且不缓存
        client-rules ip-set:iot_devices_ips -no-speed-check -address /domain-set:local_services/192.168.0.1
        client-rules AA:BB:CC:00:11:22 -group gaming_dns
        ```

#### 2.17 服务器组规则 (Group Rules - 高级)

提供一种更动态和灵活的方式来定义和匹配服务器组，通常用于非常复杂的场景。

*   **`group-begin <group_name>`**
    *   **描述**：开始定义一个名为 `<group_name>` 的服务器组的匹配规则块。
*   **`group-match [-g <target_group_name>] [-domain <domain_pattern>] [-client-ip <client_specifier>]`**
    *   **描述**：在 `group-begin` 和 `group-end` 之间使用，定义一条或多条匹配条件。如果请求同时满足 `-domain` (如果提供) 和 `-client-ip` (如果提供) 的条件，则该请求将被路由到 `<target_group_name>` (如果提供 `-g` 选项) 或者当前 `group-begin` 定义的组。
    *   **参数**:
        *   `-g <target_group_name>` (可选): 如果匹配，将请求导向此目标组。如果省略，则导向当前 `group-begin` 定义的组。
        *   `-domain <domain_pattern>` (可选): 匹配请求的域名。
        *   `-client-ip <client_specifier>` (可选): 匹配请求的客户端 IP/MAC/IP-Set。
*   **`group-end`**
    *   **描述**：结束当前服务器组的匹配规则块。
    *   **使用场景**: 当简单的 `server ... -group ...` 和 `nameserver /domain/group` 不足以描述复杂的服务器组选择逻辑时使用。例如，可以定义：如果请求来自某个特定客户端 IP 段 *并且* 查询的是特定类型的域名，则使用某个特殊的服务器组。
    *   **示例 (概念性)**:
        ```
        # 定义上游服务器并分配到基础组
        server 1.1.1.1 -group common_dns
        server 8.8.8.8 -group common_dns
        server 9.9.9.9 -group secure_dns

        group-begin high_priority_routing
            # 如果是来自内网 vip client 对 *.corp.example.com 的请求，使用 secure_dns 组
            group-match -domain /*.corp.example.com/ -client-ip 192.168.1.10 -g secure_dns
            # 其他来自内网 vip client 的请求，也使用 secure_dns (更通用的规则放后面)
            group-match -client-ip 192.168.1.10 -g secure_dns
        group-end

        # 默认情况下，所有其他请求可能走 common_dns (通过 nameserver 或全局默认)
        nameserver /.*/common_dns
        ```
    *   **注意**: `group-begin/match/end` 的具体行为和优先级可能相当复杂，需要仔细测试或查阅非常详细的文档/源码来精确掌握。

#### 2.18 插件 (Plugin)

允许加载外部动态链接库 (.so 文件) 来扩展 SmartDNS 的功能。

*   **`plugin <path_to_plugin_so_file> [plugin_specific_args...]`**
    *   **描述**：加载一个插件。
    *   **参数**：
        *   `<path_to_plugin_so_file>`: 插件共享库文件的路径。
        *   `[plugin_specific_args...]`: 传递给插件的参数，格式由插件自身定义。
    *   **示例 (SmartDNS UI 插件)**:
        ```
        plugin /usr/lib/smartdns/libsmartdns-ui.so
        smartdns-ui.www-root /usr/share/smartdns/wwwroot # UI 静态文件根目录
        smartdns-ui.ip http://0.0.0.0:6080                # UI 监听的 HTTP 地址和端口
        # smartdns-ui.ip https://0.0.0.0:6081             # UI 监听的 HTTPS 地址和端口 (如果启用)
        # smartdns-ui.cert-file /path/to/ui_cert.pem      # UI HTTPS 证书
        # smartdns-ui.key-file /path/to/ui_key.pem        # UI HTTPS 私钥
        smartdns-ui.token-expire 3600                     # UI 登录 token 过期时间 (秒)
        smartdns-ui.max-query-log-age 86400               # UI 查询日志最大保留时间 (秒)
        smartdns-ui.enable-terminal [yes|no]              # UI 是否启用内置终端功能
        smartdns-ui.enable-cors [yes|no]                  # UI 是否启用 CORS (跨域资源共享)
        smartdns-ui.user <username>                       # UI 登录用户名
        smartdns-ui.password <password>                   # UI 登录密码
        ```
    *   插件相关的配置项（如 `smartdns-ui.*`）通常由插件自身定义如何解析和使用，它们不属于 SmartDNS 核心配置指令，但通过 `conf-file` 机制或直接写在主配置文件中传递给插件。

### 3. 配置加载机制

SmartDNS 的配置加载机制负责在程序启动时读取并解析 `smartdns.conf` 文件（以及通过 `conf-file` 指令间接包含的其他配置文件），将文本化的配置指令转换为程序内部可以使用的数据结构和参数。

**核心流程如下：**

1.  **指定主配置文件**:
    *   SmartDNS 启动时，可以通过命令行参数 `-c <config_file_path>` 指定主配置文件的路径。如果未指定，则使用默认路径 (例如 `/etc/smartdns/smartdns.conf`)。

2.  **配置文件读取与解析入口**:
    *   主程序 (`smartdns_main` 在 `src/smartdns.c`) 调用 `dns_server_load_conf(config_file)` 函数 (可能在 `src/dns_conf/dns_conf.c` 或类似文件中实现) 来启动配置加载过程。

3.  **配置项定义与注册 (`_config_item[]`)**:
    *   在 `src/dns_conf/dns_conf.c` 中，有一个核心的静态数组（通常命名为 `_config_item[]` 或类似）。这个数组扮演着配置指令注册表的角色。
    *   数组的每个元素是一个结构体 (例如 `struct config_item`)，它将配置文件中的一个指令字符串 (如 "bind", "server-name", "cache-size") 映射到：
        *   一个处理该指令的回调函数（对于复杂指令）。
        *   或者，直接映射到全局配置结构体 `dns_conf` 中某个成员变量的地址和类型信息（对于简单指令）。
    *   这是通过一系列宏来实现的，例如：
        *   `CONF_STRING("directive", dns_conf.member, max_len)`: 处理字符串类型的配置。
        *   `CONF_INT("directive", &dns_conf.member, min_val, max_val)`: 处理整数类型的配置。
        *   `CONF_YESNO("directive", &dns_conf.member)`: 处理 "yes" 或 "no" 并转换为布尔值。
        *   `CONF_CUSTOM("directive", callback_function, user_data)`: 将指令交给指定的 `callback_function` 处理。
        *   `CONF_SIZE`, `CONF_ENUM_FUNC`, `CONF_STRING_LIST` 等其他宏用于不同数据类型和复杂结构。

4.  **逐行解析与分发**:
    *   `dns_server_load_conf` 函数会打开并逐行读取配置文件。
    *   对于每一非注释、非空行：
        *   提取第一个单词作为指令名。
        *   提取后续单词作为该指令的参数 (通常是空格分隔的 `argc`, `argv` 形式)。
        *   在 `_config_item[]` 注册表中查找与指令名匹配的条目。
        *   如果找到：
            *   若是 `CONF_CUSTOM` 类型，则调用其注册的回调函数，并将参数数组 (`argc`, `argv`) 以及可能的 `user_data` 传递给它。例如，`bind` 指令会调用 `_config_bind_ip_udp`，`server` 指令会调用 `_config_server_udp` 等。这些回调函数内部通常使用 `getopt_long_only` 或自定义逻辑来解析更复杂的选项 (如 `-group`, `-no-cache`)。
            *   若是其他类型 (如 `CONF_STRING`, `CONF_INT`)，相应的宏处理逻辑会负责从参数中提取值，进行类型转换和验证，并将其存入 `dns_conf` 结构体的指定成员中。

5.  **全局配置结构体 (`dns_conf`)**:
    *   几乎所有的配置解析结果最终都会存储在一个全局的结构体变量中，通常命名为 `dns_conf` (其类型可能是 `struct global_dns_conf`，定义在 `dns_conf.h` 或相关头文件中)。
    *   这个结构体聚合了 SmartDNS 运行所需的所有配置参数，例如：
        *   `dns_conf.server_name`
        *   `dns_conf.bind_ip[]` (存储所有 `bind` 指令解析结果的数组)
        *   `dns_conf.servers[]` (存储所有 `server` 指令解析结果的数组)
        *   `dns_conf.cache_size`, `dns_conf.cache_persist`
        *   各种规则列表或树的根节点 (如 `dns_conf.domain_rules_tree`, `dns_conf.ip_blacklist_tree`)。
        *   默认标志位和行为参数。

6.  **`conf-file` 指令的处理**:
    *   当解析器遇到 `conf-file <path> [-group <group_name>]` 指令时，它会：
        *   记录当前的上下文信息 (例如，如果指定了 `-group`，则后续从该文件加载的规则属于此组)。
        *   递归地调用配置加载函数来解析 `<path>` 指定的文件。
        *   支持 `glob` 通配符，`_config_foreach_file` 函数用于展开通配符并逐个处理匹配的文件。
        *   解析完被包含的文件后，恢复之前的上下文。

7.  **错误处理与日志**:
    *   在解析过程中，如果遇到无法识别的指令、参数格式错误、值超出范围等情况，SmartDNS 会记录错误日志 (级别和方式由日志配置决定)，并可能中止启动或忽略错误的配置行。

8.  **默认值的应用**:
    *   在开始解析配置文件之前，`dns_conf` 结构体的成员会被初始化为预设的默认值。如果在配置文件中没有显式设置某个配置项，则程序会使用其默认值。

**总结来说，SmartDNS 的配置加载是一个由注册表驱动的、递归的解析过程。它将结构化的文本配置文件转换为内存中易于访问的全局配置对象 `dns_conf`，后续的 DNS 服务模块将直接读取这个对象中的参数来指导其行为。**

例如，`bind :53 -group trusted -no-cache` 这一行配置：
1.  指令 `bind` 被识别。
2.  `_config_item[]` 中找到 `bind` 对应的 `_config_bind_ip_udp` (或其他协议变体) 函数。
3.  `_config_bind_ip_udp` 被调用，参数为 `":53"`, `"-group"`, `"trusted"`, `"-no-cache"`。
4.  函数内部使用 `getopt_long_only` 解析出 IP/端口、`group` 选项的值 "trusted"、`no-cache` 标志。
5.  这些信息被填充到一个 `struct dns_bind_ip` 实例中，该实例被添加到 `dns_conf.bind_ip[]` 数组。

这种机制使得添加新的配置项相对容易：只需在 `_config_item[]` 中添加新的条目，并实现相应的处理函数或在 `dns_conf` 中添加新的成员即可。

### 4. 核心服务流程

在配置加载完成并存储到 `dns_conf` 后，SmartDNS 进入核心服务流程。这一流程围绕着接收 DNS 请求、处理请求、与上游服务器交互，并最终向客户端返回响应。

#### 4.1 服务初始化与监听启动

1.  **主初始化 (`_smartdns_init` 在 `src/smartdns.c`)**:
    *   初始化日志、SSL库、Fast Ping 模块、代理模块、统计模块等基础服务。
    *   调用 `dns_server_init()` (在 `src/dns_server/dns_server.c`) 来初始化 DNS 服务端的核心组件。
    *   调用 `dns_client_init()` (在 `src/dns_client/dns_client.c`) 初始化 DNS 客户端组件，用于向上游发送请求。
    *   调用 `_smartdns_add_servers()` 将 `dns_conf.servers[]` 中配置的上游服务器信息传递给 DNS 客户端模块进行注册和管理。
    *   初始化插件。

2.  **DNS 服务端初始化 (`dns_server_init`)**:
    *   创建 `epoll` 实例：这是 SmartDNS 实现高并发异步网络 I/O 的核心。所有监听套接字和活动的客户端/服务器连接套接字都会注册到这个 `epoll` 实例中。
    *   **创建监听套接字 (`_dns_server_socket`)**:
        *   此函数遍历 `dns_conf.bind_ip_num` 和 `dns_conf.bind_ip[]` 数组（在配置加载阶段填充）。
        *   对于每一个 `struct dns_bind_ip` 条目，根据其 `type` (UDP, TCP, TLS, HTTPS):
            *   调用相应的内部函数 (如 `_dns_server_socket_udp`, `_dns_server_socket_tcp`, `_dns_server_socket_tls`)。
            *   这些函数使用标准的 socket API (`socket()`, `setsockopt()`, `bind()`, `listen()` for TCP/TLS) 来创建和配置监听套接字。
            *   如果配置了 TLS/HTTPS，还会加载 `dns_conf.bind_ca_file` 和 `dns_conf.bind_ca_key_file` 指定的证书和私钥，并创建 SSL/TLS 上下文 (`SSL_CTX`)。
            *   成功创建的监听套接字描述符会被设置为非阻塞模式，并使用 `epoll_ctl()` (通常是 `EPOLL_CTL_ADD`) 添加到 `server.epoll_fd` 中，监听 `EPOLLIN` (可读) 事件。
    *   初始化 DNS 缓存 (`_dns_server_cache_init`)：如果启用了持久化缓存，会尝试从 `dns_conf.cache_file` 加载缓存。
    *   启动服务线程/主循环的准备工作。

3.  **DNS 客户端初始化 (`dns_client_init`)**:
    *   创建独立的 `epoll` 实例供客户端模块使用，或者与服务端共享同一个 `epoll` 实例（取决于设计）。
    *   初始化上游服务器列表、服务器组等数据结构。
    *   创建 DNS 客户端工作线程 (`_dns_client_work`)。这个线程通常也基于 `epoll`，负责管理与上游服务器的连接、发送 DNS 请求、接收响应、处理超时以及调用回调函数。

4.  **进入主事件循环 (`dns_server_run`)**:
    *   程序进入一个基于 `epoll_wait()` 的主循环。
    *   `epoll_wait()` 会阻塞，直到注册的任何文件描述符上有事件发生（例如，监听套接字上有新连接，或已连接的套接字上有数据到达/可写）。

#### 4.2 DNS 请求处理生命周期

当一个 DNS 请求到达 SmartDNS 时，其处理过程大致如下：

1.  **接收请求与连接处理 (由 `epoll_wait` 唤醒)**:
    *   **新连接 (TCP/TLS/HTTPS)**: 如果是监听套接字上的 `EPOLLIN` 事件，表示有新的客户端连接请求。
        *   调用 `accept()` 接受连接，获取新的客户端套接字。
        *   对于 TLS/HTTPS，进行 SSL/TLS 握手 (`SSL_accept()`)。
        *   将新的客户端套接字注册到 `epoll` 中，监听其可读事件。
        *   为连接创建一个上下文结构 (如 `struct dns_server_conn_tcp_client`) 来维护状态。
    *   **数据到达 (UDP 或已建立的 TCP/TLS/HTTPS 连接)**: 如果是已连接套接字上的 `EPOLLIN` 事件，表示客户端发送了数据。
        *   从套接字读取数据 (`recvfrom()` for UDP, `SSL_read()`/`read()` for TLS/TCP)。
        *   对于 DoH，还需要解析 HTTP 请求，提取 DNS 报文。
        *   调用 `_dns_server_recv()` (或类似函数) 处理接收到的 DNS 报文。

2.  **请求解析与初始化 (`_dns_server_recv`)**:
    *   **解析 DNS 报文头和问题**: 从原始字节流中解析出 DNS 查询 ID, 标志位, 问题数量, 以及第一个问题中的查询域名 (`qname`) 和查询类型 (`qtype`)。存入 `struct dns_packet`。
    *   **创建请求上下文 (`_dns_server_new_request`)**:
        *   分配并初始化一个 `struct dns_request` 对象。
        *   填充客户端地址信息、查询域名、查询类型、查询 ID、初始配置 (通常是默认配置组)。
        *   关联到当前的客户端连接对象 (`request->conn`)。

3.  **应用规则与策略 (`_dns_server_setup_request_conf_pre` 和后续逻辑)**:
    *   **客户端规则匹配**: 根据 `request->conn->client_addr` (客户端 IP)，在 `dns_conf.client_rules_tree` (或类似结构) 中查找匹配的客户端规则。如果找到，该规则中定义的选项 (如特定服务器组、no-cache 等) 会覆盖 `request->conf` 中的默认值。
    *   **域名规则匹配**:
        *   **ART 树精确/前缀匹配**: 使用 `request->domain` 在当前生效的规则组 (`request->conf->domain_rule.tree`) 的 ART 树中进行查找。
        *   **正则表达式匹配**: 使用 `request->domain` 与已加载的正则表达式列表 (来自 `geosite` 文件的 `keyword:` 和 `regexp:` 条目) 进行匹配。
        *   **规则合并与优先级**: 如果同时匹配多种规则 (例如，一个精确域名规则和一个通配符规则，或者 ART 规则和正则规则)，需要根据预设的优先级（通常更精确的规则优先）来确定最终应用的规则集。
        *   将匹配到的规则（如特定的 `address` 记录、`nameserver` 组、`ipset` 名称、`no-cache` 标志等）应用到 `request` 对象上，更新其 `conf` 成员或特定字段。

4.  **处理直接应答规则**:
    *   **静态 `address` 规则**: 如果匹配到的域名规则是指定了具体 IP 地址 (非 `-`) 或 `#` (SOA):
        *   直接根据规则构建 DNS 响应报文。
        *   通过 `_dns_server_reply_address()` (或类似函数) 发送响应。
        *   审计日志。
        *   结束当前请求处理。
    *   **静态 `CNAME` 规则**: 如果匹配到 CNAME 规则:
        *   在 `request` 对象中记录 CNAME 目标。
        *   将 `request->domain` 修改为 CNAME 目标。
        *   可能会重新进入规则匹配和缓存查找阶段（针对新的 CNAME 目标域名），并有循环检测机制。

5.  **缓存查找 (`_dns_server_try_cache`)**:
    *   **条件**: 除非被 `request->conf->flags` (例如 `DNS_CONF_FLAG_NO_CACHE` 来自 `bind` 选项或域名规则) 禁用。
    *   使用 `request->domain` 和 `request->qtype` 作为键，在 DNS 缓存 (通常是哈希表) 中查找。
    *   **缓存命中 (未过期)**:
        *   从缓存中获取 IP 地址列表、CNAME 记录和 TTL。
        *   构建响应报文。
        *   审计、应用 ipset/nftset (如果适用且之前未应用)。
        *   通过 `_dns_reply_inpacket()` 发送响应。
        *   结束请求处理。
    *   **缓存命中 (已过期) 与 `serve-expired`**:
        *   如果 `request->conf->dns_serve_expired` 为 `yes`:
            *   立即使用过期数据构建响应，并使用 `request->conf->dns_serve_expired_reply_ttl` 作为 TTL。
            *   发送响应。
            *   **异步预取**: 如果 `request->conf->dns_prefetch` 也为 `yes`，则为该域名异步发起一次新的上游查询（类似步骤 6），但其结果仅用于更新缓存，不直接响应当前客户端。
            *   结束当前（对客户端的）请求处理。
        *   如果 `serve-expired` 为 `no`，则视为缓存未命中。
    *   **缓存未命中**: 继续向上游查询。

6.  **向上游服务器并发查询 (`_dns_server_do_query` -> `dns_client_query_async`)**:
    *   **确定上游服务器组**: 根据 `request->server_group_name` (来自域名规则) 或 `request->conf->default_server_group` (来自客户端规则或 `bind` 规则或全局默认)。
    *   **选择上游服务器**: 从确定的服务器组中选择一个或多个上游服务器 (`struct dns_server_info`)。选择策略可能包括：
        *   全部并发查询 (SmartDNS 的典型做法)。
        *   考虑服务器的健康状态、之前的失败率、权重等。
        *   排除已超时的或暂时不可用的服务器。
    *   **构建查询参数**:
        *   EDNS Client Subnet: 如果 `request->conf->edns_client_subnet` 或特定上游服务器的 `-subnet` 选项已配置，则构造 EDNS0 ECS 选项。
    *   **发起异步查询**: 对于每个选定的上游服务器：
        *   调用 `dns_client_query_async(server_info, request->domain, request->qtype, options, dns_server_resolve_callback, request)`。
        *   `dns_client_query_async` 会将请求加入到 DNS 客户端模块的发送队列。客户端工作线程会负责实际的网络发送 (UDP, TCP, DoT, DoH, DoQ/DoH3 连接和报文封装)。
    *   将 `request` 对象标记为等待上游响应，并可能设置一个总体超时定时器。

7.  **接收和处理上游响应 (`dns_server_resolve_callback` 被 DNS 客户端模块调用)**:
    *   当某个上游服务器返回响应，或者查询超时/出错时，DNS 客户端模块会调用注册的 `dns_server_resolve_callback` 函数，并将 `request` 对象作为用户指针传回。
    *   **错误/超时处理**: 如果是错误或超时，记录该服务器的失败，并可能影响其后续被选择的几率。
    *   **成功响应**:
        *   解析上游返回的 DNS 报文。
        *   **IP 过滤**: 应用上游服务器的 `-blacklist-ip`/`-whitelist-ip` 规则，以及全局的 `blacklist-ip`, `whitelist-ip`, `ignore-ip`, `bogus-nxdomain` 和 `ip-rules` 中定义的规则，过滤掉不符合条件的 IP 地址。
        *   将有效的 IP 地址及其 TTL 存入 `request->ip_map` (一个与当前请求关联的临时 IP 地址池)。
        *   **CNAME 处理**: 如果上游返回 CNAME 链，记录最终的权威域名，并可能需要对新的权威域名再次发起查询 (如果客户端没有进行 CNAME 追逐)。SmartDNS 通常会处理 CNAME 追逐。
        *   **测速触发**: 如果 `request->conf->flags` 未禁用测速，将新收到的、通过过滤的 IP 地址通过 `speed_check_add_ips_from_request(request)` 加入到测速队列。测速模块 (`fast_ping.c`) 会异步进行 PING 或 TCP 探测，并将结果（延迟时间）更新回 `request->ip_map` 中对应 IP 的条目。
    *   **响应模式判断**:
        *   `FASTEST_RESPONSE`: 如果这是第一个到达的有效响应，并且 `request` 尚未被响应，则直接使用此响应（经过滤和简单处理后）通过 `_dns_server_reply_passthrough()` 回复客户端，并缓存结果。请求的主要流程结束，但其他并发查询的结果仍可能用于更新测速数据和缓存。
        *   其他模式 (`FIRST_PING`, `FASTEST_IP`): 继续收集其他并发查询的结果和测速结果。

8.  **最终决策与响应 (当所有并发查询完成/超时，或满足特定响应模式的条件时)**:
    *   此阶段由 `_dns_server_query_end(request)` 或类似逻辑触发。
    *   **IP 选择 (`_dns_server_select_ip`)**:
        *   根据 `request->response_mode` 和 `request->ip_map` 中包含的 IP 及其测速结果：
            *   `FIRST_PING`: 从 `ip_map` 中选择第一个 PING 通的 IP。
            *   `FASTEST_IP`: 从 `ip_map` 中选择 PING 延迟最低的 IP。
        *   **双栈 IP 选择**: 如果 `request->conf->dualstack_ip_selection` 启用，并且 `ip_map` 中同时包含 IPv4 和 IPv6 地址，则应用双栈选择逻辑（比较延迟，考虑阈值 `dns_dualstack_ip_selection_threshold`）来决定是优先返回 IPv4、IPv6，还是两者都返回并排序。
        *   选取不超过 `request->conf->max_reply_ip_num` 数量的 IP 地址。
    *   **构建最终响应报文**: 使用选定的 IP 地址（或在无有效 IP 时返回 SOA/NXDOMAIN）填充 DNS 响应的 Answer Section。设置合适的 TTL (考虑 `rr-ttl-*` 规则和上游 TTL)。
    *   **审计日志 (`audit_log_request`)**: 记录详细的审计信息。
    *   **结果缓存 (`_dns_server_cache_add`)**:
        *   如果未禁用缓存，将最终选择的 IP 地址（以及 CNAME 链）和计算出的缓存 TTL 存入全局 DNS 缓存。
    *   **ipset/nftset 添加**: 如果 `request->conf` 中有为当前域名（或全局）配置的 `ipset_rule` 或 `nftset_rule`，则将选定的 IP 地址添加到相应的 ipset/nftset 集合中。
    *   **发送响应给客户端 (`_dns_reply_inpacket`)**: 将构建好的最终响应报文发送回客户端。
    *   **清理资源**: 释放 `request` 对象及其相关资源。

这个流程确保了 SmartDNS 能够并发地利用多个上游源，通过测速和规则智能地选择最佳结果，并高效地服务客户端请求。异步 I/O 和多线程（或等效的异步任务）是其高性能的关键。


#### 3.1 配置项定义与解析函数 (`_config_item[]`)

在 `src/dns_conf/dns_conf.c` 文件中，核心的配置项解析逻辑围绕一个名为 `_config_item[]` 的静态数组展开。这个数组的每一项都代表一个 SmartDNS 支持的配置指令。

每个 `struct config_item` 通常包含以下关键成员：

*   `name`: 字符串，表示配置文件中的指令名称，例如 "bind", "server-name", "cache-size" 等。
*   `type`: 枚举类型，指示该配置项的数据类型或特性，例如 `CONFIG_TYPE_STRING`, `CONFIG_TYPE_INT`, `CONFIG_TYPE_SERVER` 等。这有助于解析函数理解如何处理该配置项的值。
*   `offset`: (可选) 通常用于直接将解析后的值存储到全局配置结构体 (`struct dns_config`) 的特定成员中。
*   `parser_func`: 一个函数指针，指向实际处理该配置项的解析函数。当配置文件中的某一行匹配到 `name` 时，这个函数会被调用。

**解析流程简述：**

1.  **逐行读取**：`config_load()` 函数 (或其调用的子函数) 逐行读取配置文件。
2.  **指令匹配**：对于每一行，它会尝试与 `_config_item[]` 数组中的 `name` 字段进行匹配，以确定是哪个配置指令。
3.  **调用解析函数**：一旦匹配成功，相应的 `parser_func` 就会被调用。这个函数负责：
    *   从该行配置中提取参数值。
    *   验证参数的有效性（例如，检查 IP 地址格式是否正确，端口号是否在允许范围内等）。
    *   将解析后的值存储到程序内部的数据结构中，通常是全局的 `struct dns_config` 实例或其成员指向的其他动态数据结构。

#### 3.2 关键配置项的加载示例

让我们通过几个例子来看看具体配置项是如何被加载的：

*   **`bind [ip_addr][#port]`**:
    *   **匹配**: `_config_item[]` 中名为 "bind" 的项。
    *   **解析函数**: 类似于 `_config_bind()` (实际函数名可能略有不同)。
    *   **过程**:
        1.  函数会解析出 IP 地址和可选的端口号。
        2.  如果只有 IP 地址，则使用默认端口 (通常是 53)。
        3.  验证 IP 地址和端口的有效性。
        4.  将这些监听地址和端口信息存储到一个列表中，供后续创建监听套接字使用。 `struct dns_config` 中会有类似 `listen_addrs` 的成员来存储这些信息。

*   **`server <ip_addr>[#port] [-group <group_name>] ...`**:
    *   **匹配**: "server" (以及 "server-tcp", "server-tls", "server-https" 等变体)。
    *   **解析函数**: 例如 `_config_server()`。
    *   **过程**:
        1.  解析上游服务器的 IP 地址和端口。
        2.  解析可选参数，如 `-group` (服务器组)、`-no-speed-check` (禁止测速)、`-no-cache` (禁止缓存此服务器结果)、`-proxy` (指定代理) 等。
        3.  为每个上游服务器创建一个 `struct server_entry` (或类似) 的结构体实例。
        4.  将该实例添加到全局的上游服务器列表 (例如 `struct dns_config` 中的 `servers` 列表) 中。
        5.  如果指定了服务器组，还会将该服务器与对应的组关联起来。

*   **`cache-size <size_in_kb>`**:
    *   **匹配**: "cache-size"。
    *   **解析函数**: 可能是通用的整型参数解析函数，或者一个特定的 `_config_cache_size()`。
    *   **过程**:
        1.  读取 `<size_in_kb>` 的值。
        2.  验证其是否为有效的非负整数。
        3.  将其转换为字节单位，并存储到 `struct dns_config` 的 `cache_size_bytes` (类似名称) 成员中。

*   **`domain-rules /<domain_pattern>/ -nameserver <server_ip | group_name>`**:
    *   **匹配**: "domain-rules"。
    *   **解析函数**: 可能是 `_config_domain_rule()` (实际位于 `src/dns_conf/domain_rule.c` 中的相关函数)。
    *   **过程**:
        1.  解析域名模式 (例如，`*.example.com`, `example.net`)。
        2.  解析关联的动作，例如 `-nameserver` (指定使用特定的上游服务器或服务器组)、`-address` (返回指定的 IP 地址)、`-block` (阻止解析)。
        3.  这些规则被编译成内部表示（可能是正则表达式或优化的字符串匹配结构），并存储在一个规则列表中 (例如 `struct dns_config` 中的 `domain_rules` 列表)。每个规则项会包含匹配模式和相应的动作及参数。

*   **`conf-file <path_to_another_conf_file>`**:
    *   **匹配**: "conf-file"。
    *   **解析函数**: 可能是 `_config_conf_file()`。
    *   **过程**:
        1.  获取指定配置文件的路径。
        2.  递归调用主配置加载函数 (`config_load()`) 来加载这个额外的配置文件。这允许用户将配置分散到多个文件中。

#### 3.3 默认配置和错误处理

*   **默认值**: 如果某些配置项在配置文件中没有显式指定，SmartDNS 会使用预设的默认值。这些默认值通常在 `dns_config_init()` (或类似名称的初始化函数) 中设置，或者在解析函数中当参数未提供时应用。
*   **错误处理**: 配置解析过程中，如果遇到语法错误、无效参数或文件读取失败等问题，SmartDNS 会：
    *   输出错误信息到日志 (标准输出或指定的日志文件)。
    *   根据错误的严重程度，可能会忽略错误的配置行并继续，或者终止程序启动。例如，一个无法解析的 `bind` 地址可能会导致启动失败，而一个无法识别的域名规则中的参数可能只会被忽略。

通过这种结构化的方式，SmartDNS 能够灵活地处理大量配置项，并且易于扩展新的配置指令。开发者只需要在 `_config_item[]` 中添加新的条目，并实现相应的解析函数即可。

### 4. 域名服务实现

一旦配置加载完成，SmartDNS 就进入服务状态，开始监听指定的 IP 地址和端口，接收并处理 DNS 查询请求。本章将详细阐述域名服务的核心实现流程。

#### 4.1 请求的接收与解析

DNS 请求的处理始于网络数据包的接收。

1.  **监听与接收**:
    *   SmartDNS 根据 `bind` 配置项创建 UDP 和/或 TCP 套接字，并在主事件循环中 (通常使用 `epoll` 或 `select` 等 I/O 多路复用机制) 监听这些套接字上的传入数据。
    *   当有数据到达时，`_dns_server_recv()` (或类似函数，位于 `src/dns_server/dns_server.c`) 被调用。
    *   该函数负责从套接字读取原始的 DNS 请求数据包。

2.  **请求合法性检查与解析**:
    *   接收到的数据包首先会经过初步的合法性检查，例如最小长度、基本格式等。
    *   接着，`dns_request_parse()` (或类似功能的函数，可能在 `src/dns_client/` 或 `src/utils/` 目录下) 会被调用，将原始的二进制 DNS 请求报文解析为程序内部易于处理的结构体 (例如 `struct dns_request` 或 `struct message`)。
    *   这个结构体通常包含：
        *   **查询 ID (Transaction ID)**: 用于匹配请求和响应。
        *   **标志位 (Flags)**: 如 QR (Query/Response), Opcode, RD (Recursion Desired) 等。
        *   **问题段 (Question Section)**: 包含查询的域名 (QNAME)、查询类型 (QTYPE, 如 A, AAAA, CNAME, MX, NS, PTR, TXT, SRV, SOA) 和查询类 (QCLASS, 通常是 IN for Internet)。
        *   **(可选) 附加记录段 (Additional Records Section)**: 可能包含 EDNS0 相关信息，如客户端子网 (ECS)。

3.  **请求来源信息**:
    *   同时，程序会记录请求的来源 IP 地址和端口，这对于后续的响应发送和某些特定规则（如基于源 IP 的访问控制，虽然 SmartDNS 主要不强调这个）是必要的。

#### 4.2 域名匹配与规则应用

在成功解析DNS请求后，SmartDNS 会根据配置的规则和内部状态来决定如何处理这个查询。这个过程通常遵循一定的优先级。

##### 4.2.1 缓存查找 (Cache First)

这是最优先的步骤。

*   **构建缓存键 (Cache Key)**: SmartDNS 会根据查询域名 (QNAME)、查询类型 (QTYPE) 和查询类 (QCLASS) 构建一个唯一的缓存键。如果启用了 EDNS 客户端子网 (ECS) 并且 `cache-ecs-lookup` 为 `yes`，ECS 信息也可能成为缓存键的一部分。
*   **查询缓存**: 使用此键在内部 DNS 缓存中查找。
    *   **命中 (Cache Hit)**: 如果找到有效的、未过期的缓存条目：
        1.  检查缓存条目的 TTL 是否仍然有效。
        2.  如果配置了 `serve-expired yes` 或 `serve-expired-ttl` 相关的选项，并且缓存已过期但仍在宽限期内，SmartDNS 可能会返回这个过期的记录，同时异步地向上游服务器刷新该记录。
        3.  如果缓存有效，SmartDNS 会直接使用缓存中的 IP 地址列表（或其他类型的记录）来构建响应，并跳过后续的大部分处理步骤。
        4.  如果配置了 `prefetch-domain yes` 且缓存即将过期，SmartDNS 可能会在返回当前缓存结果的同时，异步向上游请求更新，以保持缓存的“新鲜度”。
    *   **未命中 (Cache Miss)**: 如果缓存中没有找到对应的条目，或者条目已过期且不符合 `serve-expired` 的条件，则进入后续的处理流程。

##### 4.2.2 域名规则匹配 (`domain-rules`, `address`, `nameserver /domain/`)

如果缓存未命中，SmartDNS 会检查针对该查询域名的特定规则。这些规则在 `src/dns_conf/domain_rule.c` 中定义和处理。

1.  **`address /<domain_pattern>/<ip_addr>`**:
    *   如果查询域名匹配 `<domain_pattern>` (可以是精确域名、通配符域名)，SmartDNS 会直接使用指定的 `<ip_addr>` (或 `#` 表示的空地址，通常用于屏蔽) 来应答。
    *   这通常用于自定义解析或屏蔽特定域名。
    *   如果匹配成功，且不是空地址，则构建响应并返回，不再向上游查询。

2.  **`domain-rules /<domain_pattern>/ action [params]`**:
    *   这是更通用的规则引擎。查询域名会与 `domain-rules` 中定义的模式进行匹配。
    *   如果匹配成功，则执行相应的 `action`：
        *   `-nameserver <server_ip | group_name>`: 将查询转发给指定的单个上游服务器或服务器组。
        *   `-address <ip_addr>`: 效果同 `address` 指令。
        *   `-block`: 阻止该域名的解析，通常返回 NXDOMAIN 或空应答。
        *   `-ttl <seconds>`: 为此规则匹配到的结果强制设定 TTL。
        *   `-ipset /<ipset_name>/[<family>]`: 将解析到的 IP 地址添加到指定的 `ipset` 集合中。
        *   `-nftset /<family>/<table>/<set_name>`: 将解析到的 IP 地址添加到指定的 `nftables set` 中。
    *   匹配顺序通常按照配置文件中的定义顺序。

3.  **`nameserver /<domain_pattern>/[<group_name>|-]`**:
    *   这是 `domain-rules` 中 `-nameserver` 动作的简化版。
    *   如果查询域名匹配 `<domain_pattern>`，则查询将仅发送给指定的上游服务器组 `<group_name>`。如果组名为 `-`，则表示该域名不走任何配置的 `server`，可能依赖系统 DNS 或返回错误。
    *   如果指定了具体的服务器组，则后续的上游服务器选择将仅限于该组内的服务器。

##### 4.2.3 黑白名单和 IP 黑名单 (`blacklist-ip`, `whitelist-ip`, `domain-set`)

*   **`domain-set /<domain_pattern>/ -blacklist` / `-whitelist`**: (通过 `set_file.c` 等处理)
    *   如果域名匹配 `domain-set` 中标记为 `-blacklist` 的规则，则该域名会被阻止解析。
    *   如果域名匹配 `domain-set` 中标记为 `-whitelist` 的规则，它可能会绕过某些后续的过滤机制（具体行为取决于实现细节和与其他规则的组合）。
*   `blacklist-ip` 和 `whitelist-ip` 配置的 IP 地址或网段在后续上游服务器返回结果后起作用。如果上游返回的 IP 地址在 `blacklist-ip` 中，则该结果会被丢弃。如果启用了 `whitelist-ip` 并且上游返回的 IP 不在白名单中，也可能被丢弃（除非配置了相应的回退策略）。

##### 4.2.4 Geosite/Domain-set 匹配 (`domain-set /.../ -file <geosite_file> -geosite ...`)

*   `geosite` 文件 (类似于 V2Ray 的 `geosite.dat`) 包含大量的域名列表，通常按国家或用途分类。
*   `domain-set` 指令可以使用 `-file <geosite_file>` 和 `-geosite <category>[:<country_code>]` 来加载这些预定义的域名列表，并为它们关联动作，如 `-nameserver <group>` 或 `-block`。
*   例如，`domain-set /./ -file /etc/smartdns/geosite.dat -geosite cn -nameserver china_dns_group` 会将所有匹配 `geosite.dat` 中 "cn" (中国) 分类的域名查询导向 `china_dns_group` 服务器组。
*   `src/dns_conf/set_file.c` 中的函数负责解析这些列表文件 (包括纯文本列表和 `geosite` 格式)。`_config_set_read_list()` 和 `_config_set_read_geosite()` 等函数会处理这些文件，将其中的域名（或域名模式）加载到内部的数据结构中，并与指定的动作（如转发到特定服务器组、阻止等）关联起来。

如果经过以上所有规则检查后，请求既没有被缓存命中，也没有被特定规则直接处理（如 `address` 或 `-block`），那么 SmartDNS 就需要向上游 DNS 服务器查询。

#### 4.3 上游服务器选择与并发查询

这是 SmartDNS 实现“最快 IP”核心功能的地方。

1.  **确定候选服务器列表**:
    *   如果之前的域名规则 (如 `nameserver /domain/group` 或 `domain-rules /domain/ -nameserver group`) 指定了特定的服务器组，则候选服务器就是该组内的成员。
    *   否则，候选服务器是所有已配置且未被标记为特定域名专用的全局上游服务器。
    *   被 `exclude-default-group yes` 标记的服务器不会参与默认的全局查询。

2.  **健康检查与测速 (`speed-check-mode`)**:
    *   SmartDNS 会定期或按需对上游服务器进行健康检查和网络延迟测速。
    *   `speed-check-mode` 配置项定义了测速的域名，例如 `ping.tcp.google.com:443,ping.tcp.baidu.com:443`。SmartDNS 会尝试连接这些目标（或进行 DNS 查询）来评估到各个上游服务器的“速度”。
    *   测速结果（通常是响应时间）会与每个上游服务器关联。
    *   如果一个服务器在健康检查中失败次数过多或响应太慢，可能会被临时禁用或降低优先级。
    *   `fast_ping` 目录下的代码 (如 `fast_ping.c`) 实现了底层的 ICMP Ping 功能，可用于某些类型的测速。对于 TCP/TLS/HTTPS 服务器，测速可能涉及建立连接或发送简单的探测请求。

3.  **服务器组策略**:
    *   如果查询被导向一个服务器组，SmartDNS 会在该组内进行选择。
    *   服务器组可以有自己的特性，例如某些组可能配置了 `-no-speed-check`，则组内服务器不参与全局测速排序，或者其结果有特定处理方式。

4.  **并发查询**:
    *   SmartDNS 不会只选择一个“最快”的上游服务器然后等待其响应。相反，它会向多个（数量可能由 `dualstack-ip-selection-threshold` 等参数间接影响，或有一个内部并发数限制）看似健康且速度较快的候选上游服务器 **并发地** 发送同一个 DNS 查询。
    *   这个并发查询是 SmartDNS 获得最快结果的关键。

5.  **结果收集与选择**:
    *   SmartDNS 等待这些并发请求的响应。
    *   **首个合法响应优先**: 一般情况下，SmartDNS 会采用最先返回的、合法的、且通过了 IP 黑白名单检查的 DNS 响应。
    *   **IP 地址排序与选择 (`fastest-ip`, `dualstack-ip-selection`)**:
        *   如果多个上游服务器在短时间内都返回了结果，并且配置了 `fastest-ip yes`，SmartDNS 会比较这些响应中 A/AAAA 记录的 IP 地址。
        *   它会根据之前对这些 IP 地址（或其所在服务器）的测速结果（不仅仅是上游服务器的延迟，也可能包括对目标 IP 本身的直接测速，虽然这更复杂）来选择“最快”的 IP 地址。
        *   `dualstack-ip-selection` 和相关阈值 (`dualstack-ip-selection-threshold`) 用于在 IPv4 和 IPv6 地址之间进行选择和排序，例如优先选择延迟更低的 IP 地址，或者在延迟相近时优先 IPv6。
        *   如果收到的响应中包含 CNAME 记录，SmartDNS 通常会递归解析 CNAME 指向的域名，直到获得最终的 A/AAAA 记录。
    *   **TTL 处理**: 会根据配置（如 `min-ttl`, `max-ttl`, `rrset-order`) 和上游返回的 TTL 来确定最终响应中的 TTL 值。

#### 4.4 结果缓存

一旦从上游服务器获得了满意的结果（或者经过了本地规则处理得到了结果），这个结果（包括查询的域名、类型、记录、TTL等）会被存入 DNS 缓存中。

*   **缓存键**: 与 4.2.1 中描述的相同。
*   **缓存内容**: 包括解析到的 IP 地址列表 (A/AAAA 记录)、MX 记录、CNAME 记录等，以及它们的 TTL。
*   **缓存淘汰**: 当缓存达到 `cache-size` 上限时，会根据一定的淘汰策略（如 LRU - Least Recently Used）移除旧的或不常用的缓存条目。
*   `negative-ttl` 和 `negative-cache` 配置项决定了对 NXDOMAIN (域名不存在) 等否定结果的缓存时间和行为。

#### 4.5 EDNS (ECS) 处理

*   **接收**: 如果客户端请求包含 EDNS0 选项，特别是 ECS (EDNS Client Subnet)，SmartDNS 会解析它。
*   **转发**: 根据 `edns-client-subnet` 的配置，SmartDNS 决定是否将 ECS 信息转发给上游服务器。
    *   如果配置了具体的 IP/掩码 (如 `edns-client-subnet 1.2.3.0/24`)，则 SmartDNS 会用这个指定的子网信息替换客户端原始的 ECS 信息（或添加 ECS 信息）再向上游转发。这有助于隐藏客户端的真实子网，同时又能为特定地理区域获得优化的 CDN 结果。
    *   如果配置为 `edns-client-subnet delete`，则会移除客户端请求中的 ECS 信息。
    *   如果配置为 `edns-client-subnet preserve yes` (或类似选项)，则会尝试保留客户端的 ECS。
*   **缓存**: 如前所述，`cache-ecs-lookup yes` 会使 ECS 信息成为缓存键的一部分，从而为不同子网的客户端缓存不同的结果。

#### 4.6 响应构建与发送

最后，SmartDNS 将选定的 DNS 记录和相关信息（如 TTL）组装成标准的 DNS 响应报文。

1.  **构建响应报文**:
    *   使用与原始请求相同的查询 ID。
    *   设置标志位 (QR=1表示响应, AA位根据情况设置, RA递归可用位通常会设置)。
    *   填充答案段 (Answer Section) 为选定的 DNS 记录。
    *   如果需要，填充授权段 (Authority Section) 和附加段 (Additional Section)。
2.  **发送响应**:
    *   将构建好的响应报文通过之前接收请求的套接字发送回客户端的源 IP 地址和端口。

这个流程构成了 SmartDNS 处理每一个 DNS 查询的核心循环。通过积极的缓存、灵活的域名规则、并发的上游查询以及智能的结果选择，SmartDNS 致力于在各种网络环境下提供快速且准确的域名解析服务。


### 5. 高级功能与集成

除了核心的 DNS 解析流程，SmartDNS 还提供了一些高级功能以及与系统集成的能力，以增强其可用性和在复杂网络环境中的适应性。

#### 5.1 日志系统

SmartDNS 提供了灵活的日志记录功能，帮助用户监控其运行状态、诊断问题以及分析 DNS 查询行为。

*   **`log-level <level>`**: 控制日志输出的详细程度。可选的级别通常包括 `fatal`, `error`, `warn`, `info`, `debug`, `trace`。级别越高，输出的信息越详细。
*   **`log-file <path>`**: 指定日志文件的路径。如果未指定，日志通常输出到标准错误流 (stderr)。
*   **`log-size <size_in_kb>`**: 当日志文件达到指定大小时，会自动进行轮转 (rotate)，旧的日志文件会被重命名（例如，`smartdns.log.1`），并创建新的日志文件。
*   **`log-num <count>`**: 指定保留轮转日志文件的数量。
*   **`log-queries yes|no`**: 是否记录每个 DNS 查询的详细信息。这对于调试特定域名的解析问题非常有用，但会产生大量的日志。
*   **日志内容**:
    *   启动和关闭信息。
    *   配置加载过程中的错误和警告。
    *   上游服务器的状态变化（例如，服务器不可达、恢复正常）。
    *   DNS 查询处理过程中的重要事件（例如，缓存命中/未命中、特定规则的应用、向上游查询的发送和接收、最终选择的结果）。
    *   错误信息，如解析失败、网络错误等。

日志系统的实现在 `src/utils/log.c` (或类似文件) 中，提供了格式化输出、级别控制、文件写入和轮转等功能。

#### 5.2 统计与运行时信息

SmartDNS 内部会维护一些统计信息，可以通过特定方式查询，以便了解其运行性能和状态。

*   **查询统计**:
    *   总查询次数。
    *   缓存命中次数、命中率。
    *   各类查询类型 (A, AAAA, MX 等) 的数量。
    *   转发到不同上游服务器或服务器组的查询数量。
*   **缓存统计**:
    *   当前缓存条目数。
    *   缓存使用的内存大小。
*   **上游服务器状态**:
    *   每个上游服务器的延迟、可用性状态、收发包数、错误数等。
*   **获取方式**:
    *   **信号**: 某些实现中，可以通过向 SmartDNS 进程发送特定信号 (如 `SIGUSR1` 或 `SIGINFO`) 来触发统计信息转储到日志文件。
    *   **控制接口/API**: 更高级的实现可能会提供一个简单的控制接口 (例如，通过特定的 TCP/UDP 端口或 Unix domain socket) 来查询运行时信息。
    *   **LuCI 界面**: 在 OpenWrt 等路由器固件上，SmartDNS 的 LuCI 界面通常会调用后端的 `ubus` 或 `rpcd` 接口来获取这些统计数据并展示给用户。`package/luci/files/luci/controller/smartdns.lua` 和 `package/luci/files/root/usr/share/rpcd/acl.d/smartdns.json` 等文件与此相关。

这些统计信息对于性能调优和监控 SmartDNS 的健康状况至关重要。

#### 5.3 `ipset` 与 `nftables` 集成

SmartDNS 能够将其解析到的 IP 地址动态地添加到 Linux 内核的 `ipset` 集合或 `nftables set` 中。这对于实现基于域名的高级防火墙规则或策略路由非常有用。

*   **配置指令**:
    *   `ipset /<domain_pattern>/<ipset_name>/[<family>]`
    *   `nftset /<domain_pattern>/<family>/<table>/<set_name>`
    *   `domain-rules /<domain_pattern>/ -ipset /<ipset_name>/[<family>]`
    *   `domain-rules /<domain_pattern>/ -nftset /<family>/<table>/<set_name>`

*   **工作流程**:
    1.  当一个 DNS 查询匹配了配置了 `ipset` 或 `nftset` 动作的域名模式时：
    2.  SmartDNS 会正常解析该域名，获取其 A (IPv4) 和/或 AAAA (IPv6) 记录。
    3.  对于解析到的每一个 IP 地址：
        *   它会检查该 IP 地址是否已经存在于目标 `ipset` 集合或 `nftables set` 中。
        *   如果不存在，SmartDNS 会调用相应的命令行工具 (`ipset add ...` 或 `nft add element ...`) 将该 IP 地址添加到指定的集合中。
        *   `family` 参数 (如 `ipv4`, `ipv6`) 确保只有对应地址族的 IP 才会被添加。
    4.  这些 IP 地址也会根据其 TTL 在 `ipset`/`nftables set` 中设置一个超时时间。当 TTL 到期后，这些 IP 地址理论上应该从集合中自动移除（ipset 支持超时，nftables set 的元素管理可能需要外部脚本配合或依赖内核的垃圾回收）。SmartDNS 本身也可能在刷新或移除缓存条目时，尝试从 set 中移除对应的 IP。

*   **实现**:
    *   这通常通过在 SmartDNS 内部调用外部命令 ( `fork` + `exec` ) 来完成。
    *   需要确保 SmartDNS 运行时具有执行 `ipset` 和 `nft` 命令的权限。
    *   错误处理机制会记录调用这些外部命令失败的情况。

*   **用例**:
    *   **域名防火墙**: 将特定分类的域名（例如，广告域名、恶意软件域名）解析到的 IP 地址加入到一个 `ipset` 黑名单中，然后用 `iptables` 或 `nftables` 规则 DROP 或 REJECT 前往这些 IP 的流量。
    *   **策略路由**: 将访问特定服务（例如，Netflix、Google）的域名解析到的 IP 加入到特定的 `ipset` 中，然后配置策略路由规则，使得访问这些 IP 的流量走特定的网络接口（例如，VPN 接口）。

`src/dns_conf/set_cmd.c` (或类似文件) 可能包含了执行这些外部命令的逻辑。

#### 5.4 预取 (Prefetching)

为了减少 DNS 解析延迟，特别是在缓存条目即将过期时，SmartDNS 支持预取功能。

*   **`prefetch-domain yes|no`**: 控制是否启用域名预取。
*   **工作机制**:
    1.  当一个 DNS 查询命中缓存，并且该缓存条目的 TTL 即将到期（例如，剩余 TTL 小于某个预设的阈值）时：
    2.  如果启用了预取，SmartDNS 会立即将当前缓存的结果返回给客户端，以保证低延迟。
    3.  同时，它会在后台异步地向上游服务器重新查询该域名，以获取最新的记录。
    4.  当新的结果返回后，它会更新缓存中的条目。
*   **优点**: 客户端总是能快速得到响应（即使是稍微有点旧的），而缓存则通过后台任务保持更新，避免了在缓存过期瞬间所有客户端请求该域名时都必须等待上游查询完成的情况。

#### 5.5 持久化缓存 (Persistent Cache)

为了在 SmartDNS 重启后能够快速恢复之前的缓存状态，减少冷启动时的延迟，支持将 DNS 缓存保存到磁盘并在启动时加载。

*   **`cache-persist yes|no`**: 是否启用持久化缓存。
*   **`cache-file <path>`**: 指定持久化缓存文件的路径。
*   **工作机制**:
    *   **保存**: 当 SmartDNS 正常关闭时 (例如，收到 `SIGTERM` 信号) 或定期地，它会将内存中的有效缓存条目序列化并写入到指定的 `cache-file` 中。
    *   **加载**: 当 SmartDNS 启动时，如果 `cache-file` 存在且有效，它会读取文件内容，反序列化这些条目，并将它们加载回内存缓存中。会检查加载的条目的 TTL，过期的条目可能会被丢弃或标记为需要立即刷新。
*   **优点**: 大大缩短了服务重启后的“预热”时间，特别是对于那些拥有大量常用域名缓存的场景。

#### 5.6 双栈 IP 选择与第二 DNS 服务 (`dualstack-ip-selection`, `second-dns-server`)

*   **`dualstack-ip-selection optimistic|strict|ipv4_only|ipv6_only`**: 控制在同时获得 IPv4 和 IPv6 地址时的选择偏好。
    *   `optimistic`: 可能基于测速结果返回最快的，或者同时返回两者。
    *   `strict`: 可能有更严格的偏好，例如，如果 IPv6 可用且速度达标，则只返回 IPv6。
    *   `ipv4_only` / `ipv6_only`: 只返回指定类型的 IP 地址。
*   **`dualstack-ip-selection-threshold <milliseconds>`**: 当 `dualstack-ip-selection` 模式允许比较 IPv4 和 IPv6 速度时，此阈值用于判断。例如，如果 IPv6 比 IPv4 慢不超过这个毫秒数，可能仍然优先选择 IPv6。
*   **`second-dns-server`**: 这是一个备用或辅助 DNS 解析机制。
    *   如果 SmartDNS 通过其常规的上游服务器和规则无法解析某个域名 (例如，所有上游都超时或返回错误，或者没有匹配的规则导向任何服务器)，它可以将这个无法处理的查询转发给 `second-dns-server` (如果已配置)。
    *   这可以作为一种最终的回退机制，例如，将本地无法解析的请求交给一个公共 DNS 或ISP的 DNS。
    *   `src/dns_server/second_dns.c` 可能是处理此逻辑的地方。

这些高级功能使得 SmartDNS 不仅仅是一个简单的 DNS 转发器，而是一个强大且可定制的 DNS 解析解决方案。

### 6. 源代码结构导览

现在为你提供一份详尽的源代码结构导览：

`src` 目录是 SmartDNS 项目的核心源代码所在，包含了实现 DNS 服务器、客户端、缓存、插件等功能的 C 语言代码。

**顶层文件 (在 `src/` 目录下):**

*   `main.c`: 程序的入口点，负责解析命令行参数、初始化 SmartDNS 环境并启动服务。
*   `smartdns.c`: SmartDNS 的主逻辑和核心功能实现，包括事件循环、信号处理等。
*   `dns.c`: 处理 DNS 协议相关的核心代码，包括 DNS 报文的解析、封装、记录类型处理等。
*   `dns_cache.c`: 实现 DNS 缓存机制，用于存储查询结果，提高响应速度并减轻上游服务器负担。
*   `dns_plugin.c`: SmartDNS 插件系统的管理和调用接口，允许通过插件扩展 SmartDNS 的功能。
*   `dns_stats.c`: 收集和报告 DNS 查询的各种统计信息，如查询次数、缓存命中率等。
*   `proxy.c`: 实现 DNS 代理功能，负责将客户端的 DNS 查询转发到配置的上游服务器。
*   `regexp.c`: 处理正则表达式相关的匹配和操作，可能用于规则匹配或过滤。
*   `timer.c`: 提供定时器功能，用于调度各种延时任务和超时处理。
*   `tlog.c`: 实现灵活的日志记录功能，用于输出程序运行信息、警告和错误。
*   `Makefile`: SmartDNS 源代码的构建文件，定义了编译规则、依赖关系和构建目标。
*   `.gitignore`: Git 版本控制忽略文件列表，指定了不需要提交到仓库的文件和目录。

**子目录:**

*   **`src/utils/`**: 包含各种通用的工具函数和辅助模块。
    *   `url.c`: URL 解析和相关操作函数。
    *   `nftset.c`: 与 Netfilter set (nftables) 相关的工具函数，用于管理 IP 地址集合。
    *   `ssl.c`: 提供 SSL/TLS 加密相关的工具函数，可能用于 DoT/DoH 等安全协议。
    *   `stack.c`: 实现通用的栈数据结构。
    *   `tls_header_parse.c`: 解析 TLS 协议头部信息。
    *   `misc.c`: 包含各种杂项实用函数。
    *   `neighbors.c`: 可能与发现网络邻居（如通过 mDNS）相关的功能。
    *   `net.c`: 提供网络相关的通用函数，如套接字创建、绑定、发送接收数据等。
    *   `capbility.c`: 处理进程能力（capabilities）相关的功能，用于权限管理。
    *   `daemon.c`: 实现将程序作为守护进程运行的功能。
    *   `dns_debug.c`: 提供 DNS 调试相关的工具和功能，可能包括报文打印、状态检查等。
    *   `ipset.c`: 与 IPset 相关的工具函数，用于管理 IP 地址集合。

*   **`src/lib/`**: 包含项目内部使用的一些库和数据结构实现。
    *   `stringutil.c`: 字符串处理工具函数集。
    *   `timer_wheel.c`: 实现时间轮算法，用于高效管理大量定时器事件。
    *   `idna.c`: 处理国际化域名 (IDNA) 的编码和解码，支持非 ASCII 域名。
    *   `nftset.c`: (与 `src/utils` 中的同名文件可能有关联或重复，需要进一步确认其具体作用)
    *   `radix.c`: 实现基数树数据结构，常用于 IP 地址的高效查找和匹配。
    *   `rbtree.c`: 实现红黑树数据结构，一种自平衡二叉查找树，用于有序数据存储。
    *   `art.c`: 实现 Adaptive Radix Tree (ART) 数据结构，用于高效的字符串或 IP 地址查找。
    *   `bitops.c`: 位操作相关的工具函数。
    *   `conf.c`: 处理 SmartDNS 配置文件解析和数据结构管理。

*   **`src/include/`**: 存放 SmartDNS 项目的公共头文件。
    *   `smartdns/`: SmartDNS 特定的头文件可能组织在此子目录下，供其他模块引用。

*   **`src/http_parse/`**: 处理 HTTP 协议的解析。
    *   `qpack.c` / `qpack.h`: 实现 QPACK (HTTP/3 头部压缩格式) 的解析和编码。
    *   `http3_parse.c` / `http3_parse.h`: 解析 HTTP/3 协议报文。
    *   `http_parse.c` / `http_parse.h`: 通用的 HTTP 协议解析代码，可能作为其他具体版本解析的基础。
    *   `http2_parse.c` / `http2_parse.h`: 解析 HTTP/2 协议报文。
    *   `http1_parse.c` / `http1_parse.h`: 解析 HTTP/1.1 协议报文。

*   **`src/fast_ping/`**: 实现快速 ping 功能，用于检测上游 DNS 服务器的可达性和延迟。
    *   `wakeup_event.c` / `wakeup_event.h`: 可能用于事件唤醒机制，提高 ping 的响应速度。
    *   `ping_udp.c` / `ping_udp.h`: 实现基于 UDP 协议的 ping 检测。
    *   `ping_tcp.c` / `ping_tcp.h`: 实现基于 TCP 协议的 ping 检测。
    *   `ping_icmp6.c` / `ping_icmp6.h`: 实现基于 ICMPv6 协议的 ping 检测。
    *   `ping_host.c` / `ping_host.h`: 处理对特定主机的 ping 操作。
    *   `ping_icmp.c` / `ping_icmp.h`: 实现基于 ICMPv4 协议的 ping 检测。
    *   `notify_event.c` / `notify_event.h`: 可能用于通知 ping 结果或事件。
    *   `ping_fake.c` / `ping_fake.h`: 可能用于模拟 ping 结果，用于测试或特定场景。
    *   `fast_ping.c` / `fast_ping.h`: 快速 ping 功能的核心实现和接口定义。

*   **`src/dns_server/`**: 包含 SmartDNS 服务器端的实现代码。
    *   `speed_check.c` / `speed_check.h`: 实现速度检测功能的核心逻辑，根据 ping 结果等选择最佳上游。
    *   `soa.c` / `soa.h`: 处理 SOA (Start of Authority) DNS 记录类型。
    *   `server_udp.c` / `server_udp.h`: 实现基于 UDP 协议的 DNS 服务器端。
    *   `server_tcp.c` / `server_tcp.h`: 实现基于 TCP 协议的 DNS 服务器端。
    *   `server_tls.c` / `server_tls.h`: 实现基于 TLS 协议的 DNS (DoT) 服务器端。
    *   `server_https.c` / `server_https.h`: 实现基于 HTTPS 协议的 DNS (DoH) 服务器端。
    *   `server_socket.c` / `server_socket.h`: 服务器端套接字相关的通用操作。
    *   `request_pending.c` / `request_pending.h`: 管理待处理的客户端请求。
    *   `rules.c` / `rules.h`: 处理各种 DNS 规则的匹配和应用，如域名规则、IP 规则等。
    *   `ptr.c` / `ptr.h`: 处理 PTR (Pointer) DNS 记录类型（反向解析）。
    *   `request.c` / `request.h`: 处理客户端 DNS 请求的生命周期，包括接收、解析、处理和响应。
    *   `mdns.c` / `mdns.h`: 实现 mDNS (Multicast DNS) 相关的功能。
    *   `neighbor.c` / `neighbor.h`: 可能与处理网络邻居的 DNS 查询相关。
    *   `prefetch.c` / `prefetch.h`: 实现 DNS 预取功能，提前解析常用域名。
    *   `ipset_nftset.c` / `ipset_nftset.h`: 可能结合 IPset 和 nftables 处理服务器端规则。
    *   `local_addr.c` / `local_addr.h`: 处理本地地址相关的逻辑。
    *   `dualstack.c` / `dualstack.h`: 处理 IPv4/IPv6 双栈相关的逻辑。
    *   `ip_rule.c` / `ip_rule.h`: 处理基于 IP 地址的规则。
    *   `connection.c` / `connection.h`: 管理服务器端网络连接。
    *   `context.c` / `context.h`: SmartDNS 服务器端上下文管理。
    *   `dns_server.c` / `dns_server.h`: SmartDNS 服务器端的总体控制和协调。
    *   `audit.c` / `audit.h`: 可能用于审计 DNS 查询和响应。
    *   `cache.c` / `cache.h`: 服务器端缓存的具体实现。
    *   `client_rule.c` / `client_rule.h`: 处理基于客户端 IP 的规则。
    *   `cname.c` / `cname.h`: 处理 CNAME (Canonical Name) DNS 记录类型。
    *   `address.c` / `address.h`: 处理 IP 地址和相关操作。
    *   `answer.c` / `answer.h`: 构建 DNS 响应报文。

*   **`src/dns_conf/`**: 处理 SmartDNS 配置文件解析和管理。
    *   `srv_record.c` / `srv_record.h`: 解析和处理 SRV DNS 记录配置。
    *   `speed_check_mode.c` / `speed_check_mode.h`: 处理速度检测模式的配置。
    *   `smartdns_domain.c` / `smartdns_domain.h`: 处理 SmartDNS 特定的域名配置。
    *   `set_file.c` / `set_file.h`: 处理集合文件（如 IPset 文件）的解析和加载。
    *   `server_group.c` / `server_group.h`: 管理上游 DNS 服务器组的配置。
    *   `server.c` / `server.h`: 解析和管理单个上游 DNS 服务器的配置。
    *   `qtype_soa.c` / `qtype_soa.h`: 处理 SOA 记录在配置中的表示。
    *   `ptr.c` / `ptr.h`: 处理 PTR 记录在配置中的表示。
    *   `proxy_server.c` / `proxy_server.h`: 处理代理服务器的配置。
    *   `proxy_names.c` / `proxy_names.h`: 处理代理名称的配置。
    *   `plugin.c` / `plugin.h`: 解析和管理插件的配置。
    *   `nftset.c` / `nftset.h`: 处理 nftset 相关的配置。
    *   `nameserver.c` / `nameserver.h`: 处理 nameserver 的配置。
    *   `ipset.c` / `ipset.h`: 处理 ipset 相关的配置。
    *   `ip_set.c` / `ip_set.h`: 处理 IP 集合的配置。
    *   `ip_alias.c` / `ip_alias.h`: 处理 IP 别名的配置。
    *   `ip_rule.c` / `ip_rule.h`: 解析和管理 IP 规则配置。
    *   `host_file.c` / `host_file.h`: 处理 hosts 文件的解析和加载。
    *   `https_record.c` / `https_record.h`: 处理 HTTPS DNS 记录配置。
    *   `get_domain.c` / `get_domain.h`: 处理获取域名的配置。
    *   `group.c` / `group.h`: 处理规则组的配置。
    *   `domain_set.c` / `domain_set.h`: 处理域名集合的配置。
    *   `domain_rule.c` / `domain_rule.h`: 解析和管理域名规则配置。
    *   `dns_conf.c` / `dns_conf.h`: DNS 配置文件的主要解析和管理入口。
    *   `dns_conf_group.c` / `dns_conf_group.h`: 处理 DNS 配置中的组。
    *   `dhcp_lease_dnsmasq.c` / `dhcp_lease_dnsmasq.h`: 可能与读取 dnsmasq 的 DHCP 租约文件相关。
    *   `dns64.c` / `dns64.h`: 处理 DNS64 功能的配置。
    *   `ddns_domain.c` / `ddns_domain.h`: 处理 DDNS (动态 DNS) 域名的配置。
    *   `cname.c` / `cname.h`: 处理 CNAME 记录在配置中的表示。
    *   `conf_file.c` / `conf_file.h`: 处理配置文件的读取和解析。
    *   `client_subnet.c` / `client_subnet.h`: 处理客户端子网的配置。
    *   `client_rule.c` / `client_rule.h`: 解析和管理客户端规则配置。
    *   `bootstrap_dns.c` / `bootstrap_dns.h`: 处理 bootstrap DNS 的配置（用于启动时解析上游服务器地址）。
    *   `bind.c` / `bind.h`: 处理绑定地址和端口的配置。
    *   `address.c` / `address.h`: 处理 IP 地址在配置中的表示。

*   **`src/dns_client/`**: 包含 SmartDNS 作为客户端向上游 DNS 服务器发送查询的代码。
    *   `wake_event.c` / `wake_event.h`: 可能用于唤醒等待上游响应的事件。
    *   `query.c` / `query.h`: 处理向上游服务器发送 DNS 查询的逻辑。
    *   `server_info.c` / `server_info.h`: 管理上游 DNS 服务器的信息，如地址、状态、延迟等。
    *   `proxy.c` / `proxy.h`: 客户端侧的代理逻辑，可能用于选择通过哪个上游代理查询。
    *   `packet.c` / `packet.h`: 客户端侧 DNS 报文的构建和解析。
    *   `pending_server.c` / `pending_server.h`: 管理等待上游服务器响应的查询。
    *   `group.c` / `group.h`: 处理客户端查询时使用的上游服务器组。
    *   `dns_client.c` / `dns_client.h`: SmartDNS DNS 客户端的总体控制和协调。
    *   `ecs.c` / `ecs.h`: 处理 ECS (EDNS Client Subnet) 选项。
    *   `conn_stream.c` / `conn_stream.h`: 管理基于流的连接（如 TCP, TLS, HTTPS, QUIC）。
    *   `client_tls.c` / `client_tls.h`: 实现基于 TLS 协议向上游发送 DNS 查询 (DoT)。
    *   `client_udp.c` / `client_udp.h`: 实现基于 UDP 协议向上游发送 DNS 查询。
    *   `client_tcp.c` / `client_tcp.h`: 实现基于 TCP 协议向上游发送 DNS 查询。
    *   `client_socket.c` / `client_socket.h`: 客户端侧套接字相关的通用操作。
    *   `client_quic.c` / `client_quic.h`: 实现基于 QUIC 协议向上游发送 DNS 查询 (DoQ)。
    *   `client_mdns.c` / `client_mdns.h`: 实现作为客户端发送 mDNS 查询。
    *   `client_http3.c` / `client_http3.h`: 实现基于 HTTP/3 协议向上游发送 DNS 查询。
    *   `client_https.c` / `client_https.h`: 实现基于 HTTPS 协议向上游发送 DNS 查询 (DoH)。

这份导览应该能帮助你理解 `src` 目录下各个文件和子目录在 SmartDNS 项目中所扮演的角色。
通过结合配置文件的指令和对这些源代码模块功能的理解，可以更全面地掌握 SmartDNS 的工作原理和内部机制。


## 附录：核心模块实现细节

### A.1 DNS 缓存模块 (`src/dns_server/server_cache.c`)

DNS 缓存是 SmartDNS 性能的关键。其实现需要高效的查找、插入、删除以及内存管理。

**A.1.1 数据结构**

SmartDNS 的缓存模块通常会使用 **哈希表 (Hash Table)** 作为主要的存储结构，以实现 O(1) 的平均查找时间复杂度。

*   **哈希表**:
    *   一个由多个 "桶" (buckets) 组成的数组。
    *   每个桶是一个链表 (or a balanced binary search tree for better worst-case performance) ，用于解决哈希冲突。
*   **缓存键 (Cache Key)**:
    *   由查询域名 (QNAME)、查询类型 (QTYPE) 和查询类 (QCLASS) 组合而成。如果 `cache-ecs-lookup yes`，还会包含 EDNS 客户端子网 (ECS) 信息。
    *   这个组合键会被哈希函数处理，得到一个哈希值，用于确定其在哈希表中的桶索引。
*   **缓存条目 (Cache Entry / `struct cache_entry`)**:
    *   存储在哈希表中的实际数据单元，通常包含：
        *   `key`: 完整的缓存键（或其组件），用于在链表内精确匹配。
        *   `message`: 指向一个存储DNS响应报文或解析后的记录数据（如 IP 地址列表、CNAME 记录、MX 记录等）的结构体。
        *   `ttl`: 该记录的原始生存时间 (Time To Live)。
        *   `expire_time`: 该记录的绝对过期时间戳 (通常是 `receive_time + ttl`)。
        *   `prefetch_time`: (如果支持预取) 预取触发时间戳。
        *   `last_access_time`: 最后访问时间戳 (用于 LRU 淘汰策略)。
        *   `ref_count`: (如果使用引用计数) 引用计数器。
        *   `flags`: 状态标志 (例如，是否为否定缓存、是否正在预取)。
        *   `next`, `prev`: 用于在哈希桶的链表中链接，以及在全局 LRU 链表中链接。

*   **LRU (Least Recently Used) 链表**:
    *   为了在缓存满时有效地进行淘汰，通常会维护一个全局的双向链表，按照缓存条目的最近使用情况排序。
    *   所有缓存条目都会在这个 LRU 链表中。当一个条目被访问时，它会被移动到链表的头部。
    *   当需要淘汰时，链表尾部的条目（即最久未使用的）会被移除。

**A.1.2 核心操作**

1.  **缓存查找 (`cache_lookup(key)`)**:
    *   计算 `key` 的哈希值，找到对应的哈希桶。
    *   遍历桶内链表，比较每个条目的完整 `key` 是否与查询 `key` 匹配。
    *   如果找到匹配且 `expire_time` 未到期（或符合 `serve-expired` 条件）：
        *   更新 `last_access_time`。
        *   将该条目移至 LRU 链表头部。
        *   返回缓存的 DNS 记录。
    *   否则，返回未命中。

2.  **缓存插入 (`cache_insert(key, data, ttl)`)**:
    *   首先检查缓存是否已满 (根据 `cache-size` 配置的内存限制或条目数量限制)。
    *   **如果已满**: 调用 `cache_evict()` 淘汰一个或多个条目。
    *   计算 `key` 的哈希值，找到对应的哈希桶。
    *   创建一个新的 `struct cache_entry`，填充数据、计算 `expire_time`。
    *   将新条目插入到对应哈希桶的链表头部。
    *   将新条目插入到 LRU 链表的头部。
    *   更新缓存的当前大小/条目数。

3.  **缓存淘汰 (`cache_evict()`)**:
    *   从 LRU 链表的尾部取出一个条目。
    *   从其所属的哈希桶链表中移除该条目。
    *   释放该条目占用的内存。
    *   更新缓存的当前大小/条目数。
    *   重复此过程，直到缓存空间足够。

4.  **缓存清理 (Periodic Cleanup)**:
    *   SmartDNS 可能会有一个后台任务或在特定时机（如每次插入前）遍历缓存，主动移除已完全过期的条目 (TTL 已耗尽且不符合 `serve-expired` 条件)，以回收内存。这比单纯依赖 LRU 更主动。

**A.1.3 持久化缓存 (`cache-persist`)**

*   **保存 (`cache_save_to_disk()`)**:
    *   遍历哈希表中的所有有效（未过期或符合持久化条件的）缓存条目。
    *   将每个条目的关键信息 (key, DNS 记录数据, expire_time) 序列化。
    *   写入到 `cache-file` 指定的文件中。格式可以是二进制的，也可以是某种文本格式 (如 JSON，但效率较低)。
*   **加载 (`cache_load_from_disk()`)**:
    *   SmartDNS 启动时，如果 `cache-file` 存在：
    *   读取文件内容，反序列化每个条目。
    *   对于每个加载的条目，检查其 `expire_time` 是否仍然有效。
    *   如果有效，则调用 `cache_insert()` 将其重新加入到内存缓存中。

**A.1.4 内存管理**

*   精确计算每个缓存条目占用的内存，并与 `cache-size` 配置进行比较。
*   使用高效的内存分配器，减少碎片。
*   在删除条目时确保所有相关内存都被正确释放。

### A.2 测速模块 (`src/dns_server/server_speed.c`, `src/fast_ping/`)

测速模块的目的是评估到上游 DNS 服务器的“速度”或可用性，以便 SmartDNS 能够优先选择响应更快的服务器。

**A.2.1 测速目标与方法**

*   **配置**: `speed-check-mode` 定义了测速的目标和方式。
    *   `ping`: 使用 ICMP Echo 请求探测上游 DNS 服务器 IP。
    *   `tcp:<port>`: 尝试与上游 DNS 服务器的指定 TCP 端口建立连接。例如 `tcp:53` (标准 DNS), `tcp:853` (DoT)。
    *   `udp:<port>`: (较少见，因为 UDP 无连接) 可能发送一个小的 DNS 查询到上游的 UDP 端口。
    *   `dot`: 专门针对 DNS over TLS 服务器的探测。
    *   `doh`: 专门针对 DNS over HTTPS 服务器的探测，可能是一个 HEAD 请求或一个小的 GET 请求。
    *   `host1:port1,host2:port2,...`: 可以配置多个探测目标，SmartDNS 会轮流或并发探测它们。
*   **探测内容**:
    *   对于 `ping`，就是标准的 ICMP Echo。
    *   对于 `tcp:<port>`，通常是尝试完成 TCP 三次握手，并可能立即关闭连接。连接建立的时间是主要的衡量指标。
    *   对于 `dot`/`doh`，除了 TCP 连接时间，还可能包括 TLS 握手时间和接收到第一个字节的时间 (TTFB)。
    *   一些实现可能会发送一个简单的、通常能快速响应的 DNS 查询 (例如，查询一个根服务器或一个众所周知的域名) 作为探测。

**A.2.2 测速执行**

1.  **周期性/按需测速**:
    *   SmartDNS 会定期 (例如，每隔几分钟或几秒钟) 对所有（或活跃的）上游服务器进行测速。
    *   也可能在特定事件触发时进行按需测速，例如，当一个服务器连续多次查询失败后。
2.  **并发探测**:
    *   为了提高效率，SmartDNS 通常会并发地对多个上游服务器或多个测速目标进行探测，而不是串行进行。
3.  **记录结果**:
    *   对于每个服务器，会记录最近几次的测速结果（例如，响应时间 RTT）。
    *   可能会使用加权平均值或滑动窗口平均值来平滑瞬时波动，得到一个更稳定的“速度评分”。
    *   记录连续失败的次数。如果一个服务器连续多次探测失败，可能会被标记为“不可用”或“慢速”，并在一段时间内降低其优先级或暂时停用。

**A.2.3 `fast_ping` 模块 (`src/fast_ping/`)**

*   如果 `speed-check-mode` 包含 `ping`，`fast_ping` 模块用于发送和接收 ICMP Echo 包。
*   通常需要原始套接字 (raw socket) 权限，这意味着 SmartDNS 可能需要以 root 用户身份运行，或者被授予 `CAP_NET_RAW` 能力。
*   实现 ICMP 包的构建、发送、超时处理、校验和计算以及响应解析。

**A.2.4 与服务器选择的集成**

*   测速结果（平均响应时间、可用性状态）是上游服务器选择算法的关键输入。
*   当 SmartDNS 需要向上游查询时，它会优先选择那些当前测速结果显示为“快速”且“可用”的服务器。
*   `dualstack-ip-selection-threshold` 等配置项也会参考这些测速数据来决定是优先 IPv4 还是 IPv6。

### A.3 规则匹配 (`src/dns_conf/domain_rule.c`, `src/dns_conf/set_file.c`, `src/dns_server/rules.c`)

SmartDNS 提供了强大的域名规则匹配系统，包括 `domain-rules`、`address`、`nameserver /domain/` 以及通过 `domain-set` 实现的 `geosite` 和 `geositelist` 功能。

**A.3.1 `domain-set` 与 Geosite/Geositelist 文件**

*   **配置 (`domain-set`)**:
    *   `-name <set_name>`: 定义集合名称。
    *   `-type [geosite|geositelist]`: `geosite` 支持 `domain:`, `full:`, `keyword:`, `regexp:` 前缀；`geositelist` 通常仅支持 `domain:` 和 `full:` (及无前缀默认的域匹配)，以优化性能。
    *   `-file /path/to/rules.txt`: 指定包含域名规则的文本文件。
*   **规则文件格式**:
    *   `domain:<domain>`: 匹配该域及其所有子域。
    *   `full:<domain>`: 仅精确匹配该域。
    *   `keyword:<text>` (`geosite` only): 内部转换为正则表达式 `^.*<text>.*$`。
    *   `regexp:<pattern>` (`geosite` only): 使用用户定义的正则表达式。
    *   无前缀: 默认为 `domain:`。
*   **协同工作**: `nameserver /domain-set:set_name/group_name` 指令将匹配 `set_name` 集合的域名查询路由到 `group_name`。

**A.3.2 规则加载机制**

1.  **`domain-set` 指令解析 (`_config_domain_set` @ `src/dns_conf/domain_set.c`)**:
    *   解析 `smartdns.conf` 中的 `domain-set` 行，提取名称、类型、文件路径。
    *   每个 `domain-set` 名称通过哈希（`dns_domain_set_name_table`）关联一个或多个规则文件定义。
2.  **从文件加载规则 (触发式)**:
    *   当 `nameserver` 或 `domain-rules` 指令引用一个 `domain-set` 时，会触发加载。
    *   `_config_domain_rule_set_each` (@ `src/dns_conf/domain_rule.c`) 遍历指定 `domain-set` 名称下的条目。
    *   `_config_domain_rule_each_from_geosite` (@ `src/dns_conf/set_file.c`) 被调用来处理 `geosite` 和 `geositelist` 类型的文件：
        *   逐行读取文件，忽略注释和空行。
        *   解析前缀，提取域名/模式。
        *   **`geositelist` 特殊处理**: 跳过 `keyword:` 和 `regexp:` 规则。
        *   **`keyword:` 转换**: 将 `keyword:text` 转换为正则表达式 `^.*text.*$`，并通过 `dns_regexp_insert()` 添加到全局正则列表。
        *   **`regexp:` 处理**: 通过 `dns_regexp_insert()` 直接添加用户定义的正则表达式。
        *   **回调传递**: 解析出的域名/模式（包括转换后的 `keyword` 模式）通过回调 `_config_domain_rule_add_callback` -> `_config_domain_rule_add`，最终被添加到核心规则存储中。

**A.3.3 域名规则的存储**

*   **核心数据结构: ART (Adaptive Radix Tree)** (`domain_rule.tree`):
    *   用于存储 `full:` 和 `domain:` 规则，以及从 `keyword/regexp` 匹配后得到的**模式字符串本身**。
    *   在存入 ART 前，域名键会经过**反转**处理 (例如 `www.google.com` -> `.com.google.www.`)。这使得通过查找反转键的前缀，能高效实现对原始域名后缀的匹配。
*   **规则节点 (`struct dns_domain_rule`)**: ART 中的相关节点会关联一个 `struct dns_domain_rule`，此结构存储该域名模式对应的具体规则动作（如 `nameserver` 指向的组、`address` 指定的 IP 等）。
*   **正则表达式存储**: 编译后的 `keyword:` 和 `regexp:` 规则对象由 `dns_regexp.c` 相关逻辑管理在一个独立的列表或结构中。

**A.3.4 域名匹配查询过程 (`_dns_server_get_domain_rule_by_domain_ext` @ `src/dns_server/rules.c`)**

1.  **查询域名预处理**: 待查询域名同样进行反转并添加 `.` 前后缀。
2.  **阶段一: ART 精确及后缀匹配**:
    *   使用 `art_substring_walk` 在 ART 中查找所有匹配反转后域名的前缀（即原始域名的精确匹配及所有有效后缀）。
    *   `_dns_server_get_rules` 回调收集关联的规则。由于 ART 的特性和域名反转，“最长后缀匹配”优先自然实现（例如 `sub.google.com` 会优先于 `google.com` 的规则，如果两者都定义了）。
3.  **阶段二: 正则表达式匹配 (若 ART 未直接命中所需规则)**:
    *   如果第一阶段 ART 查找未找到期望的规则 (例如，没有直接的 `nameserver` 规则，但可能存在正则规则可以应用)，并且系统中存在已加载的正则表达式 (`has_regexp()`)，则调用 `dns_regexp_match(original_domain, matched_pattern_buffer)`。
    *   此函数将原始查询域名与存储的正则表达式列表逐一比较。
    *   **关键点**: 若匹配成功，`dns_regexp_match` 返回**实际匹配上的正则表达式字符串本身**。然后，这个**字符串**（经过反转等处理后）将**再次作为键在 ART 中进行查找** (`art_substring_walk`)，以获取与此正则表达式模式绑定的具体规则动作（如 `nameserver` 指向的组）。
4.  **阶段三: 规则整合**: 收集到的规则根据标志位（如忽略特定类型的规则）进行调整，形成最终应用于当前查询的有效规则集。

**A.3.5 优先级小结**

*   `full:` 规则优先于 `domain:` 规则，通过 ART 的最长前缀匹配（实为最长后缀匹配）实现。
*   ART 规则 (`full/domain`) 通常优先于正则表达式规则 (`keyword/regexp`)，因为 ART 查找在前，且若找到确定性规则可能跳过正则匹配。
*   `regexp:` 与 `keyword:` 规则之间的优先级取决于它们在 `dns_regexp_match` 内部的匹配顺序（通常是插入顺序）。


### A.4 加密 DNS 协议处理 (DoT, DoH, DoQ)

SmartDNS 作为 DNS 客户端，通过支持 DoT, DoH, DoQ 协议向上游服务器进行加密查询，以增强用户 DNS 查询的隐私和安全性。这些功能的实现依赖于底层的 TLS/QUIC 库以及精密的协议处理逻辑。

**通用技术组件**:

*   **TLS 库**: 通常依赖如 **OpenSSL** 或 **GnuTLS**。这些库提供了 TLS 握手、证书验证、数据加解密等核心功能。相关的初始化、上下文创建 (`SSL_CTX_new`, `SSL_CTX_set_verify`), 证书加载 (`SSL_CTX_load_verify_locations`) 和连接 (`SSL_connect`, `SSL_read`, `SSL_write`) 等操作会在专门的 TLS/SSL 工具函数中封装，例如可能位于 `src/utils/ssl_utils.c` 或 `src/utils/tls_stream.c`。
*   **连接管理**: 为了效率，SmartDNS 会对与上游加密服务器的连接进行管理，包括连接复用（Keep-Alive）、连接池（有限数量的并发连接）、空闲超时和错误重试机制。这部分逻辑可能分散在各个协议处理模块或一个统一的连接管理器中（例如 `src/dns_client/connection_manager.c`）。
*   **配置参数**:
    *   `ssl-verify [yes|no]`: 控制是否验证服务器证书。
    *   `ca-path <path>` / `ca-file <file>`: 指定 CA 证书路径/文件用于服务器证书验证。
    *   `-hostname <name>`: 用于 TLS SNI (Server Name Indication) 和证书主机名验证。

**A.4.1 DNS over TLS (DoT)**

*   **配置**: `server-tls <ip_addr>[#port] [-hostname <name>] ...`
*   **源文件推测**:
    *   DoT 协议的特定处理逻辑可能位于 `src/dns_client/upstream_dot.c` 或集成在通用的上游处理模块如 `src/dns_client/upstream_io.c` 中，通过协议类型进行区分。
    *   TLS 连接的建立和数据收发会调用上述的 TLS 工具函数。
*   **技术实现流程**:
    1.  **TCP 连接**: 使用标准套接字 API (`socket`, `connect`) 与上游 DoT 服务器的指定 IP 和端口 (默认为 853) 建立 TCP 连接。此逻辑可能在 `src/utils/net_utils.c`。
    2.  **TLS 握手**:
        *   在已建立的 TCP 套接字上，调用 TLS 库函数（如 OpenSSL 的 `SSL_set_fd()` 后跟 `SSL_connect()`) 进行 TLS 握手。
        *   通过 `SSL_set_tlsext_host_name()` (OpenSSL) 设置 SNI (使用配置的 `-hostname` 或服务器 IP)。
        *   证书验证依据 `ssl-verify` 及 `ca-path`/`ca-file` 配置。
    3.  **DNS 报文封装与传输**:
        *   根据 RFC 7858，实际的 DNS 查询报文前会附加一个 2 字节的网络序长度字段。
        *   封装后的数据通过 TLS 加密通道发送 (如 `SSL_write()`)。
    4.  **响应接收与解析**:
        *   通过 TLS 加密通道接收数据 (如 `SSL_read()`)。首先读取 2 字节长度，然后读取指定长度的 DNS 响应报文。
    5.  **连接关闭/复用**: 查询完毕后，根据连接管理策略，TLS 连接可能被关闭 (`SSL_shutdown`, `close`) 或保持一段时间以备后续查询复用。

**A.4.2 DNS over HTTPS (DoH)**

*   **配置**: `server-https <URL> [-hostname <name>] ...` (URL 示例: `https://dns.example.com/dns-query`)
*   **源文件推测**:
    *   DoH 协议逻辑可能在 `src/dns_client/upstream_doh.c` 或通用的上游处理模块。
    *   HTTP 报文的构建和解析可能依赖 `src/http_parse/http_client.c` 或 `src/utils/http_utils.c`。
*   **技术实现流程**:
    1.  **URL 解析**: 解析配置的 URL，提取主机名、路径和端口 (默认为 443)。
    2.  **TCP 连接与 TLS 握手**: 同 DoT，与从 URL 中提取的主机和端口建立 TCP 连接并完成 TLS 握手。SNI 通常从 URL 的主机名自动设置。
    3.  **HTTP 请求构建**:
        *   将原始 DNS 查询报文作为请求体。
        *   **`POST` 方法**:
            *   请求行: `POST /dns-query HTTP/1.1` (路径从 URL 获取)。
            *   请求头:
                *   `Host: dns.example.com` (从 URL 获取)。
                *   `Content-Type: application/dns-message`。
                *   `Accept: application/dns-message`。
                *   `Content-Length: <length_of_dns_query_body>`。
                *   可能还有 `User-Agent` 等。
        *   **`GET` 方法 (若支持)**: DNS 查询报文经过 Base64URL 编码后作为 URL 的查询参数 (如 `/dns-query?dns=...`)。此时没有请求体。
        *   HTTP 请求的构建可能通过 `sprintf` 或专用的 HTTP 消息构建函数完成。
    4.  **发送 HTTP 请求**: 将构建好的 HTTP 请求通过 TLS 加密通道发送。
    5.  **接收与解析 HTTP 响应**:
        *   读取 HTTP 响应。首先解析响应行 (检查状态码，如 `200 OK`) 和响应头 (如 `Content-Type: application/dns-message`, `Content-Length`)。
        *   响应体中包含原始的 DNS 响应报文。
        *   HTTP 解析器需要处理分块传输编码 (Chunked Transfer Encoding) 如果服务器使用的话。
    6.  **连接管理**: 利用 HTTP/1.1 Keep-Alive 或 HTTP/2 (如果支持) 进行连接复用。

**A.4.3 DNS over QUIC (DoQ)**

*   **配置**: `server-quic <ip_addr>[#port] [-hostname <name>] ...`
*   **源文件推测**:
    *   DoQ 协议逻辑可能在 `src/dns_client/upstream_doq.c`。
    *   QUIC 连接的建立和流处理会依赖一个外部 QUIC 库的 C API 封装层，例如 `src/utils/quic_client.c`。
*   **技术实现流程**:
    1.  **QUIC 库初始化**: 加载并初始化所选的 QUIC 库 (如 `msquic`, `lsquic`, `quiche`)。
    2.  **QUIC 连接建立**:
        *   使用 QUIC 库提供的 API 与上游 DoQ 服务器的 IP 和端口 (RFC 9250 推荐默认端口 853，但早期实现可能用 784) 建立 QUIC 连接。
        *   QUIC 连接建立过程中自动完成 TLS 1.3 握手。SNI (使用配置的 `-hostname` 或服务器 IP) 和证书验证是此过程的一部分。
    3.  **创建 QUIC 流**:
        *   对于每个 DNS 查询，通过 QUIC API 在已建立的连接上打开一个新的双向流 (bidirectional stream)。
    4.  **DNS 报文封装与传输**:
        *   根据 RFC 9250，DNS 报文前同样需要附加一个 2 字节的网络序长度字段。
        *   封装后的 DNS 查询报文写入 QUIC 流。
    5.  **响应接收与解析**:
        *   从 QUIC 流中读取数据。首先读取 2 字节长度，然后读取 DNS 响应报文。
    6.  **流与连接管理**:
        *   一个 DNS 事务完成后，对应的 QUIC 流关闭。
        *   QUIC 连接可以保持打开状态，并发处理多个 DNS 查询（每个在独立的流上），直到空闲超时或显式关闭。

### A.5 IPv4/IPv6 双栈优化处理流程

SmartDNS 通过一系列配置和内部逻辑来优化在双栈网络环境下的域名解析，目标是根据用户策略选择合适的 IP 地址族并返回最快的结果。

**相关配置**:

*   `dualstack-ip-selection <mode>`: 核心策略，如 `optimistic`, `ipv4_only`, `ipv6_preferred` 等。
*   `dualstack-ip-selection-threshold <milliseconds>`: 比较不同地址族速度时的容忍阈值。
*   `fastest-ip [yes|no]`: 是否在同一地址族的多个 IP 中选择最快的。

**源文件推测**:

*   **查询发起**: `src/dns_server/server_query.c` 或 `src/dns_client/resolver.c` 负责向上游服务器发起查询，可能包含并发请求 A 和 AAAA 记录的逻辑。
*   **结果处理与选择**: `src/dns_server/server_response.c` 或 `src/dns_client/upstream_process.c` (或类似文件) 会包含处理上游响应、聚合结果，并根据双栈配置进行筛选和排序的逻辑。
*   **配置读取**: 全局配置（包括双栈设置）通常存储在 `struct dns_config` 中，由 `src/dns_conf/dns_conf.c` 初始化和填充。
*   **最终响应构建**: `src/dns_server/dns_server.c` 或其调用的响应构建模块，根据选择结果填充 DNS 应答报文。

**技术实现细节**:

1.  **并发查询发起**:
    *   当收到客户端查询时，如果 `dualstack-ip-selection` 模式不是 `*_only`，SmartDNS 的查询模块会为该域名生成两个并行的内部子查询：一个请求 A 记录，一个请求 AAAA 记录。
    *   这些子查询会通过上游服务器选择逻辑（考虑测速结果、服务器组等）分发给一个或多个上游服务器。
    *   实现并发可能通过非阻塞 I/O (如 `epoll` 配合多个套接字操作) 或一个轻量级任务/事件系统。每个子查询的状态（等待响应、已收到、超时）会被跟踪。

2.  **结果收集与初步处理**:
    *   当上游响应到达时，会被解析。A 记录和 AAAA 记录及其 TTL、来源服务器信息 (包括该服务器的 RTT 评估) 会被临时存储，通常与原始客户端请求关联起来。
    *   可能的数据结构：一个请求上下文结构体 (`struct client_request`) 中包含两个列表或数组，分别存放收集到的 A 记录和 AAAA 记录，每个记录项 (`struct ip_result`) 包含 IP 地址、TTL、以及一个指向来源 `struct server_entry` (含 RTT) 的指针或其 RTT 值。

3.  **执行 `dualstack-ip-selection` 逻辑**:
    *   在 `src/dns_server/server_response.c` (或类似模块) 中，会有一段核心的条件判断逻辑，根据 `g_config.dualstack_ip_selection_mode` 的值执行不同分支：
        *   **`ipv4_only`**: 清空收集到的 AAAA 记录列表。
        *   **`ipv6_only`**: 清空收集到的 A 记录列表。
        *   **`ipv4_preferred`**:
            *   检查 A 记录列表是否为空。若非空，则优先使用 A 记录。
            *   若 A 记录列表为空，则检查 AAAA 记录列表是否为空。若非空，则使用 AAAA 记录。
            *   (高级实现): 若两者皆有，且配置了阈值，可能会比较 AAAA 的平均/最佳 RTT 是否显著优于 A 的 RTT (例如 `avg_rtt_aaaa < avg_rtt_ipv4 - g_config.dualstack_ip_selection_threshold`)，如果差距巨大，即使是 `ipv4_preferred` 也可能考虑使用 AAAA (但这不常见，通常 "preferred" 意味着更强的偏好)。
        *   **`ipv6_preferred`**: 逻辑与 `ipv4_preferred` 对称。
        *   **`optimistic` / `strict`**:
            *   如果只有 A 或只有 AAAA 记录，则使用可用的。
            *   如果两者都有，计算 A 记录集合中的“最佳RTT_A”和 AAAA 记录集合中的“最佳RTT_AAAA”（可能取平均或最好值）。
            *   比较 `RTT_A` 和 `RTT_AAAA`。
            *   如果 `abs(RTT_A - RTT_AAAA) <= g_config.dualstack_ip_selection_threshold` (速度相近)：
                *   `optimistic` 模式：可能选择两者都返回，或根据一个次要偏好（如配置的全局偏好或随机）选择一个。
                *   `strict` 模式：通常有一个固定的偏好，比如优先 IPv6。如果 `RTT_AAAA` 在阈值内不比 `RTT_A` 差，则选择 IPv6，否则选择 IPv4。
            *   如果速度差异超出阈值，则选择 RTT 更小的一方。

4.  **执行 `fastest-ip` 逻辑**:
    *   在上述步骤确定了要返回的一个或两个地址族后，如果 `g_config.fastest_ip` 为 `yes`：
    *   对于每个选定的地址族（例如 A 记录），如果其结果列表 `list_of_A_records` 中有多个 IP 地址，会遍历这个列表。
    *   每个 `struct ip_result` 中应有其来源服务器的 RTT。根据这个 RTT 对 `list_of_A_records` 进行排序或选出 RTT 最低的那个 IP 地址（或前 N 个）。
    *   最终只保留“最快”的一个或几个 IP 地址用于构建响应。

5.  **响应构建**:
    *   将经过筛选和排序后的 A 和/或 AAAA 记录（及其对应的 TTL）填充到 DNS 响应报文的 Answer Section。
    *   如果最终没有可用的 IP 地址，则根据情况返回 NXDOMAIN 或 SERVFAIL。

通过上述流程，SmartDNS 在 C 代码层面结合配置参数、网络测速数据和条件逻辑，实现了灵活且以性能为导向的双栈 IP 地址选择。代码中会大量使用指针操作、结构体以及条件分支来高效地处理这些规则和数据。

### B.1 从配置加载到处理一个 DNS 请求的核心流程

```mermaid
graph TD
    subgraph 用户/客户端
        Client[DNS 客户端]
    end

    subgraph SmartDNS 服务器
        direction TB
        Startup["启动程序 (main.c)"] --> ConfigLoad["配置加载 (dns_conf.c)"]
        ConfigLoad --> ConfigData[内部配置数据结构]

        subgraph 核心服务循环
            EventLoop["网络事件循环 (epoll/poll)"]
            EventLoop --> |收到 DNS 请求| RequestReceive["接收 & 解析请求 (dns_server.c)"]
            RequestReceive --> QueryProcess["查询处理流程 (dns_server.c)"]
        end

        ConfigData --> QueryProcess
        ConfigData --> RuleMatch["规则匹配 (domain_rule.c, set_file.c)"]
        QueryProcess --> RuleMatch

        RuleMatch --> UpstreamSelect[上游服务器选择]
        UpstreamSelect --> FastPing["测速模块 (fast_ping)"]
        FastPing --> UpstreamSelect

        UpstreamSelect --> QueryForward["转发查询 (UDP, TCP, DoT, DoH, DoQ)"]
        QueryForward --> UpstreamServer[上游 DNS 服务器]

        UpstreamServer --> ResponseReceive[接收上游响应]
        ResponseReceive --> ResponseProcess["处理响应 (IPv4/IPv6 优化)"]
        ResponseProcess --> CacheUpdate["更新缓存 (server_cache.c)"]
        CacheUpdate --> |返回客户端| Client
        CacheUpdate --> Cache[DNS 缓存]
        Cache --> |查询| QueryProcess

        QueryProcess --> Log[日志系统]
        RuleMatch --> Log
        UpstreamSelect --> Log
        QueryForward --> Log
        ResponseProcess --> Log
        CacheUpdate --> Log
    end

    style ConfigData fill:#f9f,stroke:#333,stroke-width:2
    style Cache fill:#f9f,stroke:#333,stroke-width:2
    style FastPing fill:#f9f,stroke:#333,stroke-width:2
    style RuleMatch fill:#f9f,stroke:#333,stroke-width:2
    style QueryProcess fill:#ccf,stroke:#333,stroke-width:2
    style RequestReceive fill:#ccf,stroke:#333,stroke-width:2
    style ResponseReceive fill:#ccf,stroke:#333,stroke-width:2
    style ResponseProcess fill:#ccf,stroke:#333,stroke-width:2
    style UpstreamSelect fill:#ccf,stroke:#333,stroke-width:2
    style QueryForward fill:#ccf,stroke:#333,stroke-width:2
```

**图示说明：**

1.  **启动与配置加载**: 程序启动时(`Startup`)，首先进行配置加载(`ConfigLoad`)，读取 `smartdns.conf` 并解析，将配置信息存储在内部的数据结构(`ConfigData`)中，这些数据结构包括上游服务器列表、各种规则（如 `domain-set`、`geosite` 规则等）。
2.  **核心服务循环**: SmartDNS 进入一个网络事件循环(`EventLoop`)，监听来自客户端的 DNS 请求。
3.  **请求接收与处理**: 当收到 DNS 请求时，`RequestReceive` 模块负责接收和初步解析。然后进入核心的查询处理流程(`QueryProcess`)。
4.  **规则匹配**: 在 `QueryProcess` 中，会根据请求的域名应用各种配置规则(`RuleMatch`)。`RuleMatch` 模块会利用加载好的 `ConfigData` 中的规则数据结构进行匹配。特别是 `domain-set` 和 `geosite` 规则，它们有特定的匹配算法和数据结构。
5.  **上游服务器选择与测速**: 根据规则匹配的结果和 `ConfigData` 中的上游服务器列表，决定向哪些上游服务器发送查询。`UpstreamSelect` 模块可能会调用 `FastPing` 模块进行实时测速，以选择最优的上游服务器。
6.  **查询转发**: `QueryForward` 模块负责将 DNS 查询按照相应的协议（UDP, TCP, DoT, DoH, DoQ 等）发送到选定的上游 DNS 服务器(`UpstreamServer`)。
7.  **响应接收与处理**: `ResponseReceive` 模块接收来自上游服务器的响应。`ResponseProcess` 模块处理这些响应，例如进行 IPv4/IPv6 双栈优化（根据测速结果和配置，选择返回 IPv4 或 IPv6 地址）。
8.  **缓存管理**: 处理后的响应会用于更新 DNS 缓存(`CacheUpdate`)，并将结果存储在 `DNS 缓存` 中。后续对相同域名的查询可能会直接从缓存中获取(`Cache` -> `QueryProcess`)，提高响应速度。
9.  **发送响应**: 最终，处理好的响应会发送回客户端(`Client`)。
10. **日志**: 整个流程中的关键步骤都会由 `日志系统` 进行记录，方便调试和监控。


### B.2 domain-set 规则匹配流程图

这份图将侧重于一个传入的 DNS 查询是如何通过 ART 和正则表达式匹配机制，最终确定应用哪些规则的流程。

```mermaid
graph TD
    A[DNS 查询: 域名] --> B(("预处理域名<br>(反转, 加点)"))
    
    subgraph 规则匹配流程
        B --> C{"ART 查找\n基于反转域名<br>(art_substring_walk)"}
        C --> D["收集 ART 匹配规则<br>(_dns_server_get_rul)"]
        
        D --> E{"ART 是否直接命中<br>精确或后缀规则?"};

        E -- 是 --> H[整合 ART 规则];
        E -- 否 --> F{"是否存在<br>已加载的正则规则?"};

        F -- "否" --> H;
        %% 如果没有正则规则，直接整合 ART 规则 (可能为空)

        F -- 是 --> G["正则匹配<br>基于原始域名<br>(dns_regexp_match)"];
        
        G --> I{"正则是否匹配成功?"};

        I -- 是 --> J[获取匹配的<br>正则表达式字符串];
        J --> K{"ART 查找<br>基于匹配的正则字符串"};
        K --> L[收集与匹配正则关联的规则];
        L --> M[整合 ART + 正则规则];
        %% 合并从两个阶段收集到的规则

        I -- 否 --> H;
        %% 如果正则未匹配，整合仅从第一阶段 ART 收集的规则 (可能为空)

        H --> N["应用规则忽略标志<br>(_dns_server_update_rule_by_flags)"];
        M --> N;
    end

    N --> O[生成最终适用的\n域名规则集];

    O --> P{"根据规则集选择\n上游服务器或应用动作"};
    P --> Q[发送查询到上游\n或返回本地地址等];
    %% 后续流程...
    Q --> R[接收上游响应];
    R --> S["处理响应\n(缓存, 测速, 排序)"];
    S --> T[返回最终结果给客户端];

    %% 定义样式 (可选，为了图更清晰)
    classDef decision fill:#f9f,stroke:#333,stroke-width:2px;
    class E,F,I decision;
```

**图示说明:**

1.  **DNS 查询**: 流程从 SmartDNS 接收到一个用户的 DNS 查询请求开始。
2.  **预处理域名**: 查询的域名会被反转并添加点前缀/后缀，以适应 ART 的后缀匹配查找。
3.  **ART 查找**: 使用反转后的域名在 SmartDNS 内部存储 `full:` 和 `domain:` 规则的 ART (Adaptive Radix Tree) 中进行查找。
4.  **收集 ART 匹配规则**: 查找过程中，会收集所有匹配该域名的后缀（对应于 ART 中的前缀）所关联的规则。最长后缀匹配的规则通常会优先或覆盖短后缀规则。
5.  **ART 是否直接命中**: 判断第一阶段的 ART 查找是否直接找到了适用于当前域名的规则。
6.  **是否存在已加载的正则规则**: 如果 ART 没有直接命中（或者需要检查更广范围的规则），并且 SmartDNS 中加载了 `keyword:` 或 `regexp:` 类型的正则表达式规则，则进入正则匹配阶段。
7.  **正则匹配**: 使用原始域名与所有已加载的正则表达式进行匹配尝试。
8.  **正则是否匹配成功**: 判断是否有任何正则表达式匹配了当前域名。
9.  **获取匹配的正则表达式字符串**: 如果匹配成功，获取实际匹配上的那个正则表达式字符串。
10. **ART 查找（基于匹配的正则字符串）**: 使用这个匹配到的正则表达式字符串作为键，再次在 ART 中查找，以获取与该特定正则模式关联的规则（例如 `nameserver /regexp:^.*google.*$/group_a` 这样的配置）。
11. **收集与匹配正则关联的规则**: 收集第二阶段 ART 查找得到的规则。
12. **整合规则**: 将第一阶段 ART 收集到的规则和第二阶段（如果进行了且有匹配）正则关联的规则进行整合。
13. **应用规则忽略标志**: 根据规则中可能包含的忽略标志（如 `ignore-nameserver`），调整最终的规则集。
14. **生成最终适用的域名规则集**: 得到经过所有匹配和过滤后，最终适用于当前查询域名的规则集合。
15. **根据规则集选择上游服务器或应用动作**: SmartDNS 根据这个最终规则集，决定将查询发送到哪个上游服务器组，或者应用 `address`、`bogus-nxdomain` 等其他动作。
16. **发送查询/返回结果**: 执行上一步决定的动作（发送查询、返回本地地址等）。
17. **后续流程**: 图中简单表示了接收响应、处理（缓存、测速、排序）和返回结果的后续步骤。

这个图详细展示了 SmartDNS 如何结合 ART 高效处理 `full`/`domain` 规则以及如何通过正则匹配和二次 ART 查找处理 `keyword`/`regexp` 规则，最终确定一个查询适用的规则集合。
