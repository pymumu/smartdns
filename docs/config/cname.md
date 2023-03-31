---
hide:
  - toc
---

# cname别名查询

某些情况下，需要将a域名的查询，使用b域名的结果，比如某些CDN速度的优化，此时可以使用cname别名查询功能。

## 配置步骤

1. 使用`cname /a.com/b.com`配置别名。

    ```shell
    cname /a.com/b.com
    ```

    上述例子，查询a.com时，将会使用b.com的查询结果。
