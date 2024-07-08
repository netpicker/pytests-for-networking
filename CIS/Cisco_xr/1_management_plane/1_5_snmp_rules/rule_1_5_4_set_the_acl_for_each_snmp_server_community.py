from comfy.compliance import medium


@medium(
      name='rule_1_5_4_set_the_acl_for_each_snmp_server_community',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_5_4_set_the_acl_for_each_snmp_server_community(commands, ref):
    assert '' in commands.chk_cmd, ref
