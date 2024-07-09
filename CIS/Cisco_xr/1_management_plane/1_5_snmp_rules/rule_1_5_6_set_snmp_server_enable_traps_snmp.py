from comfy.compliance import medium


@medium(
      name='rule_1_5_6_set_snmp_server_enable_traps_snmp',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_5_6_set_snmp_server_enable_traps_snmp(commands, ref):
    assert '' in commands.chk_cmd, ref
