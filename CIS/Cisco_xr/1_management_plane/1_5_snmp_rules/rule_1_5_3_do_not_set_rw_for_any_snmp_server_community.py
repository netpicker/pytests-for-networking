from comfy.compliance import medium


@medium(
      name='rule_1_5_3_do_not_set_rw_for_any_snmp_server_community',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_5_3_do_not_set_rw_for_any_snmp_server_community(commands, ref):
    assert '' in commands.chk_cmd, ref
