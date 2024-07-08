from comfy.compliance import low


@low(
      name='rule_1_5_7_set_priv_for_each_snmp_server_group_using_snmpv3',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_5_7_set_priv_for_each_snmp_server_group_using_snmpv3(commands, ref):
    assert '' in commands.chk_cmd, ref
