---
hide:
  - toc
---

# CNAME Alias Query

In some cases, it is necessary to use the results of the query of domain B for the query of domain A, such as the optimization of the speed of some CDN. At this time, you can use the CNAME alias query function.

## Configuration Steps

1. Use `cname /a.com/b.com` to configure the proxy server

    ```shell
    cname /a.com/b.com
    ```

    In the above example, when querying a.com, the query result of b.com will be used.
