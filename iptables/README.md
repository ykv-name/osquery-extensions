iptables Extension
==================

This extension adds a new `iptables_ext` table that provides a superset of the
functionality in the default `iptables` table.

## Schema

| Column        | Type    | Description                                              |
|:--------------|:--------|:---------------------------------------------------------|
| filter_name   | TEXT    | Packet matching table name.                              |
| chain         | TEXT    | Name of the chain.                                       |
| ruleno        | INTEGER | (1-based) index of this rule within the table and chain. |
| target        | TEXT    | Name of the match target.                                |
| match         | TEXT    | A string representation of the rule's match entries.     |
| protocol      | TEXT    | Matched protocol, e.g. `tcp`.                            |
| src_port      | TEXT    | Source port range.                                       |
| dst_port      | TEXT    | Destination port range.                                  |
| src_ip        | TEXT    | Source IP address.                                       |
| src_mask      | TEXT    | Source IP's mask.                                        |
| iniface       | TEXT    | Inbound interface.                                       |
| iniface_mask  | TEXT    | Inbound interface's mask.                                |
| dst_ip        | TEXT    | Destination IP address                                   |
| dst_mask      | TEXT    | Destination IP's mask.                                   |
| outiface      | TEXT    | Outbound interface.                                      |
| outiface_mask | TEXT    | Outbound interface's mask.                               |
| packets       | BIGINT  | The number of packets evaluated by the rule.             |
| bytes         | BIGINT  | The number of bytes evaluated by the rule.               |
| reject_with   | TEXT    | The packet rejection method.                             |

## Usage

```sql
SELECT * from iptables_ext;
SELECT * from iptables_ext where target = "ACCEPT";
```

## License

The code in this repository is licensed under the [Apache 2.0 license](../LICENSE).
