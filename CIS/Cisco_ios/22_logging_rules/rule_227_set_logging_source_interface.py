from comfy.compliance import medium


@medium(
    name='rule_227_set_logging_source_interface',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_227_set_logging_source_interface(configuration, ref):
    assert 'logging source' in configuration, ref
