---
hide:
  - toc
---

# Rule Group

SmartDNS supports rule groups, which allow for filtering rules based on domain or client matching.

The relevant parameters are:

| Parameter | Function |
|--|--|
| group-begin [-g\|group group-name] | Begin a rule group |
| group-end  | End a rule group |
| group-match  | Match conditions for rule group, can be set to domain or client IP |
| conf-file -group  | Include files in the specified rule group, equivalent to group-begin, group-end  


You can specify matching rules using group-match, including client IP: `-client-ip cidr`, and domain: `-domain`.

## Matching Rule Groups by Domain or Client IP

  ```
  # Rule begins, named as rule.
  group-begin rule
  # Set matching rules, as follows for matching IP or domain.
  group-match -client-ip 192.168.1.1/24 -domain a.com
  # Set related rules
  address #
  # Rule ends
  group-end
  ```

## Including File Rule Groups

You can also include external files to handle rule groups, making it easier to maintain and manage.

The main file includes external files, and `-group` specifies the rule group name.

  ```
  conf-file client.conf -group rule
  ```

Included rule files, specifying matching conditions

  ```
  group-match -client-ip 192.168.1.1/24 -domain a.com
  address #
  ```