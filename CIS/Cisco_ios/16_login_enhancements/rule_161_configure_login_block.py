from comfy.compliance import low


@low(
    name='rule_161_configure_login_block',
    platform=['cisco_xe']
)
def rule_161_configure_login_block(configuration, ref):
    assert 'login block' in configuration, ref
