from comfy.compliance import low


@low(
    name='rule_2312_set_ntp_authentication_key',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_2312_set_ntp_authentication_key(configuration, ref):
    assert 'ntp authentication-key' in configuration, ref
