from comfy.compliance import medium


@medium(
    name='rule_214_set_no_service_dhcp',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_214_set_no_service_dhcp(configuration, ref):
    assert 'service dhcp' not in configuration, ref
