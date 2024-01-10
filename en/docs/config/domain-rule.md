---
hide:
  - toc
---

# Domain Rules

To facilitate setting multiple rules for the same domain, smartdns provides the `domain-rules` parameter, which allows you to set multiple rules for a domain.

## Rule Settings

Use `domain-rules` to set multiple rules, for example:

  ```
  domain-rules /a.com/ -g group -address #6 -ipset ipset
  ```

  Please refer to the configuration options for more information on the `domain-rules` options.

  | Parameter | Function                                  |
  |---|---|
  |`-group`|Set the corresponding rule group|
  |`-address`|Set domain address|
  |`-nameserver`|Set upstream server group|
  |`-speed-check-mode`|Set speed check mode|
  | `-no-dualstack-selection` | Disable dual-stack speed test |
  |`-no-cache`|No cache|
  | `-no-cache` | Stop caching                               |
  | `-no-ip-alias` |Ignore IP alias rules|
  | `-ipset [ipsetname]` |Put the corresponding request result into the specified ipset|
  | `-nftset [nftsetname]` |Put the corresponding request result into the specified nftset|


## Domain Wildcards

The prefix wildcard matches the main domain name

  ```shell
  # prefix wild card
  *-a.example.com
  # only match subdomains
  *.example.com
  # only match the main domain name
  -.example.com
  ```

  Note: * and - are only supported at the beginning of the domain name. Wording in other locations is not supported.

## Domain Set

When using domain sets in options with `/domain/` configuration, you only need to replace `/domain/` with `/domain-set:[set name]/`, for example:

  ```shell
  domain-set -name ad -file /etc/smartdns/ad-list.conf
  domain-rules /domain-set:ad/ -a #
  ```

  ```shell
  domain-set -name ad -file /etc/smartdns/ad-list.conf
  domain-rules /domain-set:ad/ -a #
  ```
