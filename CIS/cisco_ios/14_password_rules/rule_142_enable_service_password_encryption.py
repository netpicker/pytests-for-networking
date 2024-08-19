from comfy.compliance import medium


@medium(
    name='rule_142_enable_service_password_encryption',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_142_enable_service_password_encryption(configuration, ref):
    assert 'no service password-encryption' not in configuration, ref
