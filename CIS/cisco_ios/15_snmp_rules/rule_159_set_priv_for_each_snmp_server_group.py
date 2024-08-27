from comfy.compliance import low


@low(
    name='rule_159_set_priv_for_each_snmp_server_group',
    platform=['cisco_ios_xe'],  # Targeting Cisco IOS XE as specified
    commands={'show_snmp_group': 'show snmp group'}
)
def rule_159_set_priv_for_each_snmp_server_group(configuration, commands, device, devices):
    snmp_groups_output = commands.show_snmp_group.splitlines()
    snmp_v3_priv_groups = [
        line for line in snmp_groups_output
        if 'v3' in line and 'auth' in line and 'priv' in line
    ]

    # Verify at least one SNMPv3 group has 'priv' configured
    error_msg = "No SNMPv3 group with 'priv' found. Configure at least one group with encryption."
    assert snmp_v3_priv_groups, error_msg

    # Ensure each group uses at least AES128 encryption
    insufficient_enc_msg = "Group {group} configured with insufficient encryption. Use at least AES128."
    for group in snmp_v3_priv_groups:
        assert 'AES128' in group or 'AES' in group, insufficient_enc_msg.format(group=group)
