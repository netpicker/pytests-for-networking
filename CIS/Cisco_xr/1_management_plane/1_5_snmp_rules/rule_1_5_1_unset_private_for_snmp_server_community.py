from comfy.compliance import medium


@medium(
      name='rule_1_5_1_unset_private_for_snmp_server_community',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_5_1_unset_private_for_snmp_server_community(commands, ref):
    assert '' in commands.chk_cmd, ref