from comfy.compliance import medium


@medium(
  name='rule_152_unset_private_for_snmp_server_community',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_152_unset_private_for_snmp_server_community(configuration, ref):
    assert 'snmp-server community private' not in configuration, ref
