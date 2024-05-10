from comfy.compliance import medium


@medium(
    name='rule_226_set_service_timestamps_debug_datetime',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_226_set_service_timestamps_debug_datetime(configuration, ref):
    assert 'service timestamps debug datetime' in configuration, ref
