from comfy.compliance import medium


@medium(
    name='rule_154_do_not_set_rw_for_any_snmp_server_community',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_154_do_not_set_rw_for_any_snmp_server_community(configuration, ref):
    assert 'RW' in configuration, ref
