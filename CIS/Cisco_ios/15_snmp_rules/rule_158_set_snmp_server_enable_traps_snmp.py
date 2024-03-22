from comfy.compliance import medium


@medium(
  name='rule_158_set_snmp_server_enable_traps_snmp',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_158_set_snmp_server_enable_traps_snmp(configuration, ref):
    assert 'snmp-server enable traps' in configuration, ref
