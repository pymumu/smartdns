
## SmartDNS `domain-set` Geosite/Geositelist 功能及域名匹配机制分析与优化建议

### 1. 引言

本文档旨在深入分析 `smartdns-with-geosite` (SmartDNS 的一个 fork 版本) 中 `domain-set` 的 `geosite` 和 `geositelist` 类型的实现方式，以及它们如何与 `nameserver` 指令协同工作以实现高级域名解析策略。同时，本文也将探讨针对此域名匹配过程的一些潜在优化建议。

SmartDNS 是一个本地 DNS 服务器，通过从多个上游服务器查询并将最快的结果返回给客户端来提升网络访问速度。此 fork 版本增强了 `domain-set` 功能，使其能够更好地处理来自文本文件的域名列表（如 geosite 数据），以实现灵活的域名服务器分组和流量控制。

### 2. `domain-set` 配置与功能

#### 2.1 `geosite` 和 `geositelist` 类型

在 `smartdns.conf` 文件中，可以如下配置 `geosite` 或 `geositelist` 类型的 `domain-set`：

```
domain-set -name <set_name> -type [geosite|geositelist] -file /path/to/domain_rules.txt
```

*   `-name <set_name>`: 域名集合的唯一名称。
*   `-type [geosite|geositelist]`: 指定类型。
*   `-file /path/to/domain_rules.txt`: 包含域名规则的文本文件路径。

#### 2.2 规则文件格式与前缀

规则文件为纯文本，每行一条规则，支持以下前缀：

1.  `domain:<domain_name>`: **域匹配** (如 `domain:google.com` 匹配 `google.com` 及其所有子域)。
2.  `full:<domain_name>`: **完整匹配** (如 `full:example.com` 仅匹配 `example.com`)。
3.  `keyword:<keyword_text>`: **关键字匹配** (仅 `geosite` 支持，如 `keyword:google` 匹配含 "google" 的域名，内部转为正则 `^.*google.*$`)。
4.  `regexp:<regex_pattern>`: **正则表达式匹配** (仅 `geosite` 支持)。
5.  **无前缀**: 默认为**域匹配**。

文件中以 `#` 开头的行为注释。

#### 2.3 `geosite` 与 `geositelist` 的区别

*   **`geosite`**: 支持所有四种匹配前缀，功能更全面。
*   **`geositelist`**: **仅支持** `domain` 和 `full` 匹配（及默认域匹配），不支持 `keyword` 和 `regexp`。设计上可能为了在处理大规模精确域名列表时有更高性能，避免了正则开销。

#### 2.4 规则匹配优先级

1.  `full:`
2.  `domain:`
3.  `regexp:` (按文件导入顺序)
4.  `keyword:` (按文件导入顺序)

(注：`regexp` 和 `keyword` 优先级及顺序主要受其后续在 `domain-rules` 或 `nameserver` 中如何被引用的影响，以及 `dns_regexp_match` 内部的匹配逻辑。)

### 3. `nameserver` 与 `domain-set` 的协同

`nameserver` 指令可将匹配特定 `domain-set` 的域名查询路由到指定的上游服务器组。

```smartdnsconf
domain-set -name geosite_google -type geosite -file /etc/smartdns/geosite_google.txt
server 8.8.8.8 -group google_dns_group
nameserver /domain-set:geosite_google/google_dns_group
```

当一个域名查询（如 `mail.google.com`）进来时，如果它匹配了 `geosite_google` 集合中的规则 (例如 `domain:google.com`)，则该查询会被转发到 `google_dns_group`。

### 4. 深入理解：规则加载实现细节

规则的加载始于 `smartdns.conf` 的解析，并涉及到从指定文件读取和处理每一条域名规则。

#### 4.1. `domain-set` 指令解析

*   **配置文件解析**: 当 SmartDNS 启动或重载配置时，它会解析 `smartdns.conf` 文件。
*   **`_config_domain_set` 函数 (位于 `src/dns_conf/domain_set.c`)**: 此函数专门负责处理 `domain-set` 配置行。
    *   它使用 `getopt_long_only` 来解析命令行参数式的选项，如 `-name`, `-type`, 和 `-file`。
    *   解析到的信息被用来填充一个 `struct dns_domain_set_name` 结构体实例，该实例包含了 `type` (如 `DNS_DOMAIN_SET_GEOSITE`, `DNS_DOMAIN_SET_GEOSITELIST`) 和 `file` (文件路径)。
    *   每个 `struct dns_domain_set_name` 实例会根据其 `-name` 参数通过哈希计算（`hash_string`）被添加到一个全局的哈希表 `dns_domain_set_name_table` 中。这个哈希表允许多个规则文件与同一个 `domain-set` 名称关联（形成一个列表 `set_name_list`），尽管通常一个 `domain-set` 定义对应一个文件。

#### 4.2. 从文件加载规则

*   **触发加载**: 当配置文件中的其他指令（如 `nameserver /domain-set:my_rules/...` 或 `domain-rules /domain-set:my_rules/...`）引用一个已定义的 `domain-set` 时，SmartDNS 会查找该 `domain-set` 的元数据（类型和文件路径）。
*   **`_config_domain_rule_set_each` 函数 (位于 `src/dns_conf/domain_rule.c`)**: 此函数会遍历指定 `domain-set` 名称下的所有条目（通常是一个）。根据条目的类型 (`set_name_item->type`)，它会调用相应的加载函数。
*   **`_config_domain_rule_each_from_geosite` 函数 (位于 `src/dns_conf/set_file.c`)**: 对于 `DNS_DOMAIN_SET_GEOSITE` 和 `DNS_DOMAIN_SET_GEOSITELIST` 类型，此函数被调用来处理规则文件。
    *   **文件打开与逐行读取**: 使用 `fopen` 打开 `-file` 指定的文件，并通过 `fgets` 逐行读取内容。
    *   **注释与空行处理**: 以 `#` 开头的行或内容为空（或仅含换行符）的行会被忽略。
    *   **前缀解析与域名提取**:
        *   使用 `sscanf(line, "%255s", domain)` 初步提取行内容。
        *   通过 `strncmp` 检查是否存在如 `full:`, `domain:`, `keyword:`, `regexp:` 等前缀。
        *   如果存在前缀，则从原始字符串中移除前缀部分，得到纯粹的域名或模式。例如，对于 `full:example.com`，提取出 `example.com`。
        *   **`geositelist` 类型的特殊逻辑**: 如果当前 `domain-set` 的类型是 `DNS_DOMAIN_SET_GEOSITELIST`，并且行中的规则是 `keyword:` 或 `regexp:` 类型，则该行规则会被直接跳过，不进行加载。
        *   **`keyword:` 规则转换**: 如果是 `keyword:somekey`，提取 `somekey` 后，会将其构造成一个正则表达式，如 `sprintf(domain,"^.*%s.*$", buf)`，其中 `buf` 存储的是 `somekey`。然后调用 `dns_regexp_insert(domain)` 将此新生成的正则表达式添加到全局的正则规则列表中。
        *   **`regexp:` 规则处理**: 如果是 `regexp:pattern`，提取 `pattern` 后，直接调用 `dns_regexp_insert(domain)` 将用户定义的正则表达式添加到全局正则规则列表中。
        *   **无前缀规则**: 如果没有上述特定前缀，该行内容被视为一个域名，默认按 `domain:` 规则处理。
    *   **回调机制传递规则**:
        *   对于每一条成功解析的域名/模式（经过前缀处理和 `keyword` 转换后），会调用一个传入的 `callback` 函数。
        *   在 `_config_domain_rule_set_each` 调用 `_config_domain_rule_each_from_geosite` 时，传入的 `callback` 通常是 `_config_domain_rule_add_callback`。
        *   `_config_domain_rule_add_callback` 内部会调用 `_config_domain_rule_add`。此函数是规则添加的核心，它接收处理后的域名/模式字符串、规则类型（如 `DOMAIN_RULE_NAMESERVER`, `DOMAIN_RULE_ADDRESS_IPV4` 等，这里主要是指后续应用到这些域名的动作类型）以及具体的规则数据。
        *   `_config_domain_rule_add` 负责将这些域名/模式（经过反转等键处理）及其关联的规则动作存入到 ART (Adaptive Radix Tree) 数据结构中。对于原始是 `keyword` 或 `regexp` 的规则，虽然它们本身被 `dns_regexp_insert` 处理，但它们所代表的模式字符串（如 `^.*somekey.*$`）也会作为键被 `_config_domain_rule_add` 添加到 ART 中，以便后续 `nameserver` 或 `domain-rules` 指令可以引用这些模式并绑定具体的动作。

通过这一系列步骤，`domain-set` 文件中定义的规则被逐条解析、处理（包括类型转换和特殊类型跳过），并最终通过回调函数整合进 SmartDNS 核心的规则存储和匹配系统中。

### 5. 深入理解：域名匹配实现细节

#### 5.1 域名规则的存储

*   **核心数据结构：ART (Adaptive Radix Tree)**
    *   对于 `full:` 和 `domain:` 规则，域名（以及从 `keyword/regexp` 匹配后得到的模式字符串）在存入 ART 前会经过**反转**处理。例如，`www.google.com` 变为 `.com.google.www.`。这种处理使得后续可以通过前缀查找实现高效的后缀匹配。
    *   ART (`domain_rule.tree`) 被用于存储这些反转后的域名键。每个 SmartDNS 配置组 (`dns_conf_group`) 维护自己的 ART。
*   **规则节点 (`struct dns_domain_rule`)**
    *   ART 中的每个相关节点会关联一个 `struct dns_domain_rule`。
    *   此结构包含一个 `rules[DOMAIN_RULE_MAX]` 数组，用于存储该域名模式对应的各种具体规则（如 `nameserver`、`address` 等）。
    *   还包含 `sub_rule_only` 和 `root_rule_only` 标志，用于更精确地控制规则的应用范围（仅子域、仅根域或两者）。
*   **正则表达式的存储**
    *   `keyword:` 和 `regexp:` 规则在 `_config_domain_rule_each_from_geosite` 中通过 `dns_regexp_insert()` 进行处理，它们被编译并存储在一个独立的列表或结构中，由 `dns_regexp.c` (未在当前分析中详述，但从函数名推断) 相关逻辑管理。

#### 5.2 域名匹配查询过程

匹配过程主要由 `src/dns_server/rules.c` 中的 `_dns_server_get_domain_rule_by_domain_ext` 函数驱动：

1.  **域名预处理**:
    *   待查询的域名同样进行反转和添加 `.` 前后缀（如 `www.google.com` -> `.com.google.www.`）。
2.  **阶段一：ART 精确及后缀匹配**:
    *   使用 `art_substring_walk` 在 ART 中查找所有匹配反转后域名的前缀。这相当于查找原始域名的所有有效后缀及其精确匹配。
        *   例如，对于 `.com.google.www.`，会查找 `.`, `.com.`, `.com.google.`, `.com.google.www.`。
    *   `_dns_server_get_rules` 回调函数被触发，收集与这些 ART 节点关联的 `struct dns_domain_rule` 中的具体规则，并考虑 `sub_rule_only` / `root_rule_only` 标志。
    *   由于 `art_substring_walk` 的特性和回调处理，通常更长（更精确）的后缀匹配规则会自然覆盖较短的，实现了“最长后缀匹配优先”。
3.  **阶段二：正则表达式匹配 (若 ART 未直接命中)**:
    *   如果第一阶段 ART 查找未直接找到规则 (`!walk_args.match`) 并且系统中存在已加载的正则表达式 (`has_regexp()`)，则进入此阶段。
    *   调用 `dns_regexp_match(domain, matched_pattern_buffer)`，将原始查询域名与存储的正则表达式列表逐一比较。
    *   **关键点**: 如果匹配成功，`dns_regexp_match` 会返回实际匹配上的那个**正则表达式字符串本身**。然后，这个**字符串**（经过反转等处理后）将再次作为键，在 ART 中进行查找 (`art_substring_walk`)，以获取与此正则表达式模式关联的具体规则（如 `nameserver` 地址）。
        *   这意味着，一个 `keyword:` 或 `regexp:` 规则若要实际生效（例如指定一个特定的上游服务器），不仅需要在 `domain-set` 文件中定义，还需要在 `smartdns.conf` 的其他地方（如 `domain-rules` 或 `nameserver` 指令）明确引用这个正则表达式字符串（或其所属的 `domain-set`），从而将一个具体的操作（action）与这个模式绑定。
4.  **阶段三：规则整合与最终化**:
    *   所有收集到的规则会经过 `_dns_server_update_rule_by_flags` 处理，根据 `DOMAIN_RULE_FLAGS` 中的忽略标志（如 `DOMAIN_FLAG_NAMESERVER_IGNORE`）进行调整。
    *   最终，`request->domain_rule` 结构中包含了所有适用于当前查询域名的、经过优先级和标志调整后的有效规则集合。

#### 5.3 优先级实现机制总结

*   **`full:` vs `domain:`**: ART 的“最长前缀匹配”（由于域名反转，实为“最长后缀匹配”）特性自然保证了更精确的规则优先。
*   **ART 规则 (full/domain) vs 正则表达式规则 (keyword/regexp)**: 代码逻辑显示，先进行 ART 查找。如果 ART 查找成功 (`walk_args.match` 为真)，则可能跳过后续代价较高的正则表达式匹配步骤。这符合 `full/domain` 规则优先于 `regexp/keyword` 的设计。
*   **`regexp:` vs `keyword:`**: 两者都作为正则表达式处理。它们之间的优先级取决于 `dns_regexp_match` 内部的匹配顺序（通常是它们被插入的顺序）。

### 6. 域名匹配优化建议

基于上述分析，以下是一些潜在的优化方向：

1.  **正则表达式预编译与共享**:
    *   **建议**: 确保所有从 `geosite` 文件加载的 `keyword:` 和 `regexp:` 规则在 SmartDNS 启动或配置重载时仅编译一次。
    *   **理由**: 正则表达式编译是耗时操作。如果多个 `domain-set` 或规则文件使用了完全相同的正则表达式字符串，它们应该共享同一个已编译的正则对象实例，以减少内存占用和重复编译开销。

2.  **优化正则表达式匹配顺序**:
    *   **建议**: 如果存在大量正则表达式规则，考虑根据其统计匹配频率或特异性（匹配范围大小）来排序匹配。将匹配频率高或特异性强（能更快确定匹配或不匹配）的规则放在前面。
    *   **理由**: `dns_regexp_match` 目前可能是按插入顺序遍历。优化顺序可以减少平均匹配时间。但这需要额外的统计或启发式逻辑。

3.  **审视正则匹配后的二次 ART 查找**:
    *   **现状**: 当前 `keyword/regexp` 匹配成功后，使用匹配到的正则表达式字符串作为键再次查询 ART 以获取具体动作。
    *   **建议**: 评估是否可以将已编译的正则表达式对象直接与动作（如 `struct dns_domain_rule` 的指针或其子规则）关联起来，例如通过一个独立的哈希表（键为编译后的正则对象，值为动作指针）或在正则对象结构中直接包含动作。
    *   **理由**: 这可能减少一次 ART 查找，简化逻辑。但需注意，当前设计可能允许同一个正则表达式字符串在配置文件中被不同规则（如不同的 `nameserver` 指向不同group）复用其“键”的角色。优化时需保持这种灵活性或评估其必要性。

4.  **使用更快的正则表达式引擎 (如果适用)**:
    *   **现状**: 项目 `ReadMe.md` 提及编译 `cre2`，它是 Google RE2 的 C 接口。RE2 以其线性的最坏情况时间复杂度（避免灾难性回溯）而闻名，通常是一个很好的选择。
    *   **建议**: 确认 `cre2` 确实是当前实现中用于 `dns_regexp_match` 的引擎。如果未来考虑替换，需仔细评估性能和兼容性。

5.  **针对超大规模规则集的内存和缓存优化 (高级)**:
    *   **建议**: 对于包含数十万甚至数百万条 `full/domain` 规则的极端情况，可以研究 ART 的内存压缩技术或针对特定访问模式优化其节点布局以改善 CPU 缓存命中率。
    *   **理由**: 虽然 ART 本身效率较高，但在极端规模下，内存和缓存仍可能成为瓶颈。这通常需要非常底层的优化。

6.  **引入布隆过滤器 (Bloom Filter) 进行正则初筛 (高级)**:
    *   **建议**: 在迭代匹配大量正则表达式之前，可以使用布隆过滤器对查询域名进行一次快速检查。如果布隆过滤器判定域名不可能匹配任何一个正则表达式，则可以跳过整个正则匹配列表。
    *   **理由**: 可以显著减少对不匹配域名的无效正则比较次数。但布隆过滤器有误报率，且需要额外维护。

7.  **性能分析 (Profiling)**:
    *   **建议**: 针对性地使用性能分析工具（如 `perf`）对 SmartDNS 在加载和处理大规模、复杂 `domain-set` 规则时的行为进行分析。
    *   **理由**: 这是找出实际性能瓶颈（ART 操作、特定正则表达式、内存分配等）的最直接方法，从而指导优化方向。

### 7. 结论

SmartDNS 的 `smartdns-with-geosite` fork 通过引入 `geosite` 和 `geositelist` 类型的 `domain-set`，并结合 ART 和反向域名存储等技术，提供了一套强大且相对高效的域名规则管理和匹配机制。理解其内部实现有助于更好地利用其功能，并为进一步的性能优化提供了基础。上述优化建议提供了一些可能的改进方向，但具体实施需要结合实际场景和性能分析结果进行权衡。
