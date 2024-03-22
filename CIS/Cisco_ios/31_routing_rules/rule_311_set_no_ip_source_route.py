from comfy.compliance import medium


@medium(
    name='rule_311_set_no_ip_source_route',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_311_set_no_ip_source_route(configuration, ref):
    assert 'no ip source-route' in configuration, ref
