---
hide:
  - toc
---

# Fallback DNS

Set up Fallback DNS, which acts as a fallback DNS to provide query services when the primary DNS fails or does not respond.

1. Use the `-fallback` parameter to designate a specific server as the fallback DNS.

    ```shell
    server -fallback
    ```

1. Equivalent configuration method:

    Use the `-e -group fallback` options together, which is equivalent to the above configuration.

    ```shell
    server -e -group fallback
    ```