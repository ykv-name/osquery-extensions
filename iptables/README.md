iptables Extension
==================

This extension adds a new `iptables_ext` table that provides a superset of the
functionality in the default `iptables` table.

## Schema

| Column        | Type    | Description |
|:--------------|:--------|:------------|
| filter_name   | TEXT    | foo         |
| chain         | TEXT    | foo         |
| ruleno        | INTEGER | foo         |
| target        | TEXT    | foo         |
| match         | TEXT    | foo         |
| protocol      | TEXT    | foo         |
| src_port      | TEXT    | foo         |
| dst_port      | TEXT    | foo         |
| src_ip        | TEXT    | foo         |
| src_mask      | TEXT    | foo         |
| iniface       | TEXT    | foo         |
| iniface_mask  | TEXT    | foo         |
| dst_ip        | TEXT    | foo         |
| dst_mask      | TEXT    | foo         |
| outiface      | TEXT    | foo         |
| outiface_mask | TEXT    | foo         |
| packets       | BIGINT  | foo         |
| bytes         | BIGINT  | foo         |
| reject_with   | TEXT    | foo         |

## Usage

```sql
SELECT * from iptables_ext;
SELECT * from iptables_ext where target = "ACCEPT";
```

## License

The code in this repository is licensed under the [Apache 2.0 license](../LICENSE).
