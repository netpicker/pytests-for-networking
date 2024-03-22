from comfy.compliance import medium


@medium(
    name='rule_221_set_logging_enable',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_221_set_logging_enable(configuration, ref):
    assert 'logging enable' in configuration, ref
