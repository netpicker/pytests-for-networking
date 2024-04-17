from comfy.compliance import medium


@medium(
    name='rule_153_unset_public_for_snmp_server_community',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_153_unset_public_for_snmp_server_community(configuration, ref):
    assert 'snmp-server community public' not in configuration, ref
