from comfy.compliance import medium


@medium(
    name='rule_222_set_buffer_size_for_logging_buffered',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_222_set_buffer_size_for_logging_buffered(configuration, ref):
    assert 'logging buffered' in configuration, ref
