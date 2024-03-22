from comfy.compliance import medium


@medium(
    name='rule_21111_set_the_hostname',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_21111_set_the_hostname(configuration, ref):
    assert 'hostname' in configuration, ref
