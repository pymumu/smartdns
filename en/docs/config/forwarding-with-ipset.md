---
hide:
  - toc
---

# Whitelist dns forwarding request

## Flow process

The functions that need to be implemented for dns forwarding are as follows:

* Internal domain obtains IP by querying internal DNS server, and measures the speed of IP to return the fastest IP address to the client.
* External domain queries from external server, external domain manages IP data through domain list, and the IP data is transparently forwarded through TPROXY.

The corresponding process diagram is as follows:

``` mermaid
%%{init: {'theme':'forest'}}%%
flowchart 
    style client color:white,fill:#dd5555,stroke:#ee00,stroke-width:2px
    style ipset color:white,fill:green,stroke:#ee00,stroke-width:2px
    style ipset1 color:white,fill:green,stroke:#ee00,stroke-width:2px
    style speed-check color:white,fill:green,stroke:#ee00,stroke-width:2px
    client(((Client)))-----> |1. Request|smartdns
    smartdns---->|2. Obtain IP|client
    client--->|3. Request data using IP|router
    subgraph smartdns [SmartDNS&nbsp&nbsp]
        server(DNS service)-->|a.Handling namserver rules|rule(domain name rules)
        rule-->|b.External domains|public-group(external server group)
        rule-->|b.Internal domains|private-group(internal server group)
        public-group-->|d. Add IP to IPSet|ipset1(IPSet,NFTSet)
        private-group-->|d. Measuring the speed and obtain the fastest IP address|speed-check(Measuring speed)
    end
    router-->ipset(IPSet,NFTSet)
    subgraph router [Routing gateway]
        NAT-->|a. Receive data packet|ipset-->|b. Data forwarding|tproxy(TPROXY forwarding service)
    end
    tproxy----->|VPN|ProxyServer
    tproxy----->|SOCKS5|ProxyServer
    tproxy----->|HTTP PROXY|ProxyServer

    public-group--->|c.Query external domain|public-servers(external DNS server)
    private-group--->|c.Query internal domain|private-servers(internal DNS server)

```

  1. The client queries the domain name to the SmartDNS server.
  1. SmartDNS processes requests.
    1. Determine the domain name according to the rules given by namserver.
    1. If the domain name is an internal domain name, use the internal domain name server for the query. If the domain name is an external domain name, use the external domain name server for the query.
        1. For internal domain names, use the speed measurement function to obtain the fastest IP address.
        1. For external domain names, after obtaining the fastest response DNS result, add the IP address to the IPSet/NFTSet.
    1. SmartDNS returns the IP address.
  1. The client obtains the IP address from SmartDNS.
  1. The client requests data using the IP address through the gateway.
  1. The gateway receives the data packet and judges the IP rule using IPSet/NFTSet.
    1. If the IP is in the IPSet/NFTSet (external domain name), use TPROXY to send the data to the remote proxy server.
    1. If IP does not exist in IPSet/NFTSet (internal domain name), it is directly forwarded by NAT.

## SmartDNS forward configuration

In the above process diagram, SmartDNS forward data needs to be set as follows

* The internal domain obtains IP by querying the internal DNS server, and measures the speed of IP to return the fastest IP address to the client.
* The external domain queries from the external server, does not measure the speed, and adds the IP address to the IPSet/NFTSet for data forwarding.

1. Basic configuration

    Enable the SmartDNS service and set the relevant functions.

    ```shell
    # Enable the server
    bind [::]:53
    # Enable speed measurement
    speed-check-mode ping,tcp:80,tcp:443
    # Enable dual stack optimization
    dualstack-ip-selection yes
    # Enable caching and persistence
    cache-size 32768
    cache-persist yes
    prefetch-domain yes
    serve-expired yes
    ```

1. Add DNS server

    Add upstream server and specify internal and external server groups with `-group` parameter.

    ```shell
    # External server group
    server 1.2.3.4 -group public

    # Internal server group
    server 1.2.3.4 -group private
    ```

    Note:

    1. It is recommended to configure multiple external and internal servers.
    2. The `public` external server group can choose to configure the `-exclude-default-group` parameter to avoid internal domain name queries through external servers.
    3. The `public` external server group can use the `proxy-server` option to configure query through socks5, http proxy, so that the results will be better.

1. Configure domain name policy

    Configure blacklist domain names, use the `public` server group for domain names in the list, turn off speed measurement, turn off IPV6, and join IPSET.

    ```shell
    # Add domain name list, format one domain name per line
    domain-set -name public-domain-list -file /path/to/public/domain/list

    # Set the corresponding domain name list rules.
    domain-rules /domain-set:public-domain-list/ -ipset public  -nftset #4:ip#table#set -c none -address #6 -nameserver public
    ```

    Note:

    1. The domain name list can be configured to automatically update at fixed intervals using crontab, and the format is one domain name per line.

        ```shell
        a.com
        b.com
        ...

        ```

    1. In domain name rules:
        1. -ipset represents adding results to the corresponding ipset name, `public` is an example, and can be modified to the corresponding ipset name as needed.
        2. -nftset represents adding the result to the corresponding nftset name, `#4:ip#table#set` is an example and needs to be modified to the corresponding ipset name.
        3. -c none: Disables speed measurement, and specific parameters refer to speed-check-mode.
        4. -address #6: Disables IPV6. If the forwarding program supports IPV6, this parameter can be omitted.
        5. -nameserver public: Indicates using the DNS server of the public group to resolve the results.

## IPSET and transparent forwarding rule configuration

To cooperate with smartdns to complete the forwarding of external requests, it is necessary to configure related ipset and rules. The specific configuration steps are as follows:

1. Create IPSet

    Execute a shell command to create IPSET.

    ```shell
    # Create ipset collection
    ipset create public hash:net
    ```

1. Configure rules in SmartDNS.

    ```shell
    ipset /example.com/public
    ```

1. Set up transparent forwarding rules:

    Transparent forwarding in Linux is divided into TPROXY and REDIRECT two modes. These two modes have the following differences in use and can be selected for configuration as needed.

    Mode: TPROXY, REDIRECT

    TPROXY: Supports UDP, TCP forwarding, slightly complicated configuration.  
    REDIRECT: Only supports TCP and configurations are simple.

    1. Approach One: TCP forwarding only (easy)

        * Set rules

            ```shell
            # Set forwarding rules to redirect matching requests to port 1081 on the local machine
            iptables -t nat -I PREROUTING -p tcp -m set --match-set public dst -j REDIRECT --to-ports 1081
            ```

        * Enable forwarding program

            The local 1081 port opens the forwarding program in REDIRECT mode.

        * Delete rules

            ```shell
            iptables -t nat -D PREROUTING -p tcp -m set --match-set public dst -j REDIRECT --to-ports 1081
            ```

    1. Approach Two: TCP/UDP TPROXY forwarding

        Execute a shell command to set the iptable rules to transparently forward TCP/UDP requests that match the domain name, according to the TPROXY method, to the local machine's port 1081, reference rules are as follows:

        * Set rules

            ```shell
            # Set routing rules
            ip rule add fwmark 1104 lookup 1104
            ip route add local 0.0.0.0/0 dev lo table 1104

            # Set TPROXY forwarding rules for UDP and TCP modes, and forward the data to port 1081 on the local machine
            iptables -t mangle -N SMARTDNS
            iptables -t mangle -A SMARTDNS -p tcp -m set --match-set public dst -j TPROXY --on-ip 127.0.0.1 --on-port 1081 --tproxy-mark 1104
            iptables -t mangle -A SMARTDNS -p udp -m set --match-set public dst -j TPROXY --on-ip 127.0.0.1 --on-port 1081 --tproxy-mark 1104
            iptables -t mangle -A SMARTDNS -j ACCEPT
            iptables -t mangle -A PREROUTING -j SMARTDNS
            ```

        * Enable forwarding program

            The local 1081 port opens the forwarding

        * Deletion rules:

        ```shell
        ip rule del fwmark 1104
        iptables -t mangle -D PREROUTING -j SMARTDNS
        iptables -t mangle -F SMARTDNS
        iptables -t mangle -X SMARTDNS
        ```

## NFTSET and transparent forwarding rule configuration

1. Method 1: TCP forwarding only (easier)

    1. Create nftable's nftset collection, collection name is `#4:ip#nat:public_set`

       ```shell
       nft add set ip nat public_set { type ipv4_addr\; flags interval\; auto-merge\; }
       ```

    1. Set REDIRECT forwarding rule

       ```shell
       nft add rule ip nat PREROUTING meta l4proto tcp ip daddr @public_set redirect to :1081
       ```

    1. Configure nftable rules in smartdns

       ```shell
       nftset /example.com/#4:ip:nat:public_set
       ```

    1. Enable forwarding program

       Redirect mode forwarding program on local port 1081.

    1. Note that you can create a separate forwarding table for easy management as follows. Create smartdns table, name the nftset `#4:ip#smartdns#public`

        ```shell
        # Create smartdns table
        nft add table ip smartdns
        # Create NFTSET collection
        nft add set ip smartdns public { type ipv4_addr\; flags interval\; auto-merge\; }
        # Set forwarding rule
        nft add chain ip smartdns prerouting { type nat hook prerouting priority dstnat + 1\; }
        nft add rule ip smartdns prerouting meta l4proto tcp ip daddr @public redirect to :1081
        ```

        ```shell
        # Delete table
        nft delete table ip smartdns
        ```

1. Method 2: TPROXY mode forwarding TCP and UDP

    1. Configure rules

        ```shell
        # Set routing rules
        ip rule add fwmark 1104 lookup 1104
        ip route add local 0.0.0.0/0 dev lo table 1104
    
        # Create smartdns table
        nft add table ip smartdns
        # Create NFTSET collection
        nft add set ip smartdns public { type ipv4_addr\; flags interval\; auto-merge\; }
        # Set forwarding rule
        nft add chain ip smartdns prerouting { type filter hook prerouting priority 0\; }
        nft add rule ip smartdns prerouting meta l4proto tcp ip daddr @public tproxy to :1081 mark set 1104
        nft add rule ip smartdns prerouting meta l4proto udp ip daddr @public tproxy to :1081 mark set 1104
        ```

        ```shell
        # View rules
        nft list table ip smartdns
        ```

        ```shell
        # Delete existing rules
        nft delete table ip smartdns
        ```

    1. Configure nftset in smartdns

        ```shell
        nftset /example.com/#4:ip#smartdns:public
        ```

    1. Enable forwarding program

       TPROXY mode forwarding program on local port 1081.

## Additional instructions

If using the OpenWrt luci interface, domain routing rules can be configured directly in the interface.
