# Extended Netpicker Examples

This folder contains additional Netpicker rule examples for network compliance and validation.

| File                             | Test Name                       | Description                                           | Platform    | Tags       |
|----------------------------------|----------------------------------|-------------------------------------------------------|-------------|------------|
| `snmp_trap_hosts_only_expected.py` | SNMP Trap Host Validation       | Ensures only allowed SNMP trap hosts are configured  | `cisco_ios` | `monitoring` |
| `ha_bgp_prefix_consistency.py`    | HA BGP Prefix Consistency       | Verifies all BGP neighbors advertise identical routes | `fortinet`  | `fw_test`   |
| snmp_config_hosts_only_expected.py | SNMP Trap Host Validation (Config-based) | Validates SNMP trap host IPs from full config | cisco_ios, arista_eos |  |

