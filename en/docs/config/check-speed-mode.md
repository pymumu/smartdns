---
hide:
  - toc
---

# Speed Test Mode

SmartDNS can modify the speed test mode and response mode. These two modes affect the performance and results of queries.

| Mode | Parameter | Explanation |
| --- | --- | ---
| Speed test mode | speed-check-mode | SmartDNS speed test mode
| Response mode | response-mode | Result response mode |

## Speed test mode configuration

SmartDNS provides two speed test modes, namely ping and tcp. Smartdns defaults to use three tests. The first one is ping, the second one is tcp on port 80, and the third one is tcp on port 443. The speed test mode can be modified through speed-check-mode.

1. Global speed test mode configuration

    ```shell
    speed-check-mode ping,tcp:80,tcp:443
    speed-check-mode tcp:443,ping
    speed-check-mode none
    ```

    Options:

    * ping indicates using ping mode, tcp:port number indicates using tcp connection to the corresponding port
    * none indicates not to perform speed test
    * Trigger of speed test options: When three speed test modes are configured, SmartDNS first uses the first one, 200ms later, the second one is used, and 400ms later, the third one is used.

1. Single domain speed test mode configuration

    ```shell
    domain-rule /example.com/ -speed-check-mode ping,tcp:80,tcp:443
    ```

1. Turn off speed test when querying corresponding ports

    ```shell
    bind [::]:53 -no-speed-check
    ```

1. Extra

    If the domain names that need to be routed are forwarded through forwarding programs, consider turning off the speed test function of the forwarding domain name to avoid the reverse effect caused by inconsistent speed tests and exports, and close the speed test of specific domain names as follows:

    ```shell
    domain-rule /example.com/ -speed-check-mode none
    ```

## Response mode configuration

SmartDNS supports setting the first request response mode through `response-mode`. These three modes affect the query results and response time, and SmartDNS uses an optimized plan by default, but users can also make modifications as needed. The functions and performance of these three modes are as follows:

| Mode | Configuration | Delay | Result | Explanation |
| --- | --- | --- | --- | ---
| Fastest ping response address mode | first-ping | Moderate | Possibly second best | Fastest upstream DNS query delay + shortest ping delay, best query waiting and linking experience (currently the default)
| Fastest IP address mode | fastest-ip | Long | Best | The IP address with the shortest ping among all queried IP addresses. The longest DNS query time and the shortest IP link. (Previous mode)
| Fastest response DNS mode | fastest-response | Short | Possibly worst | Shortest DNS query waiting time.

For cached data after enabling cache function, the results are best regardless of which method is used, so it is not recommended to disable cache.

## Set return mode for specified domain name

1. In some cases, it may be necessary to set the response mode of a specific domain name to improve the Internet experience. You can configure the following parameters

    ```shell
    domain-rules /example.com/ -r first-ping
    domain-rules /example.com/ -response-mode fastest-response
    ```
