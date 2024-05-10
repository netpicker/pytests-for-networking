from comfy.compliance import medium


@medium(
    name='rule_141_set_password_for_enable_secret',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_141_set_password_for_enable_secret(configuration, ref):
    assert 'enable secret' in configuration, ref
