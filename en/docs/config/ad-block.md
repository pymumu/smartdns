---
hide:
  - toc
---

# Ad Blocking

SmartDNS can block ads by returning SOA for the corresponding domain name.

Note: If you're using OpenWrt with LuCI, please refer to OpenWrt's domain blocking configuration method.

## Basic Configuration Method

1. Block ads via `address /domain/#` option, for example:

    ```shell
    address /example.com/#
    ```

    In the `address` option:

    * `/domain/` uses a suffix matching algorithm that includes its subdomains;
    * `#` alone indicates both IPv4 and IPv6 blocking;
    * use `#6` to block IPv6 only;
    * use `#4` to block IPv4 only;
    * use `-` to unblock this domain.

1. Block IPv6 only:

    ```shell
    address /example.com/#6
    ```

1. If you want to unblock a particular subdomain:

    ```shell
    address /sub.example.com/-
    ```

## Usage of Domain Set

For a single domain name blocking, you can conveniently use the address parameter to block it. For more domain names, you can block it through the domain-set, which is more convenient to manage the list of advertising domain names.

Use `domain-set` to configure the collection file, such as:

```shell
domain-set -name ad -file /path/to/adblock.list
address /domain-set:ad/#
```

The format of `adblock.list` is one domain per line, such as:

```shell
a.com
b.com
...
```

## Using Community SmartDNS Ad-Blocking Lists

The community provides regularly updated ad-blocking list files for SmartDNS. You can directly use these ad-blocking list files, and add them to SmartDNS as an option with `conf-file`. Additionally, you can download and update these files periodically, then restart SmartDNS to take effect.

1. Download the configuration file to the `/etc/smartdns` directory:

    ```shell
    wget https://github.com/privacy-protection-tools/anti-AD/blob/master/anti-ad-smartdns.conf -o /etc/smartdns/anti-ad-smartdns.conf
    ```

1. Modify the `/etc/smartdns/smartdns.conf` file to include the above configuration file:

    ```shell
    conf-file /etc/smartdns/anti-ad-smartdns.conf
    ```

## Ad Blocking Lists

| Project | Description | Configuration File |
| -- | -- | --
| [anti-AD](https://anti-ad.net/) | Anti Advertising for smartdns | https://anti-ad.net/anti-ad-for-smartdns.conf |
| [adrules](https://adrules.top/) | AdRules SmartDNS List | https://adrules.top/smart-dns.conf |

## Non-SmartDNS List Format

For non-SmartDNS data, simple shell commands can convert it.

### hosts Format

The following command converts the `/path/to/hosts/file` file (replace the path with your actual file) to the format supported by SmartDNS:

```shell
cat /path/to/hosts/file | grep -v "^#" | awk '{print "address /"$2"/#"}' > anti-ad-smartdns.conf
```

### dnsmasq Format

The dnsmasq format is similar to SmartDNS, but not compatible. You can convert it using the following command:

```shell
cat /path/to/dnsmasq/file  | grep address | awk -F= '{print "address "$2"#"}' > anti-ad-smartdns.conf
```
