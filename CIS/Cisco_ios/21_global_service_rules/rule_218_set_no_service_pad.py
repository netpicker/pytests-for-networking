from comfy.compliance import medium


@medium(
    name='rule_218_set_no_service_pad',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_218_set_no_service_pad(configuration, ref):
    assert 'no service pad' in configuration, ref
