from comfy.compliance import medium


@medium(
      name='rule_1_5_5_set_snmp_server_host_when_using_snmp',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_5_5_set_snmp_server_host_when_using_snmp(commands, ref):
    assert '' in commands.chk_cmd, ref
