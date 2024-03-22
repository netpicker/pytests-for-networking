from comfy.compliance import medium


@medium(
    name='rule_157_set_snmp_server_host_when_using_snmp',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_157_set_snmp_server_host_when_using_snmp(configuration, ref):
    assert 'snmp-server host' in configuration, ref
