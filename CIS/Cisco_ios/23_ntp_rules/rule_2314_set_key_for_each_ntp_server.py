from comfy.compliance import low


@low(
    name='rule_2314_set_key_for_each_ntp_server',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_2314_set_key_for_each_ntp_server(configuration, ref):
    assert 'ntp server {} key' in configuration, ref
