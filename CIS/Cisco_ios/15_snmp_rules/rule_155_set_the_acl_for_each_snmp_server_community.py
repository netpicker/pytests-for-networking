from comfy.compliance import medium


@medium(
    name='rule_155_set_the_acl_for_each_snmp_server_community',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_155_set_the_acl_for_each_snmp_server_community(configuration, ref):
    assert r'snmp-server community \d+ ' in configuration, ref
