from comfy.compliance import medium


@medium(
    name='rule_215_set_no_ip_identd',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_215_set_no_ip_identd(configuration, ref):
    assert 'no ip identd' in configuration, ref
