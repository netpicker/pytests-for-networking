from comfy.compliance import low


@low(
    name='rule_2311_set_ntp_authenticate',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_2311_set_ntp_authenticate(configuration, ref):
    assert 'ntp authenticate' in configuration, ref
