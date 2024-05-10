from comfy.compliance import low


@low(
    name='rule_2313_set_the_ntp_trusted_key',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_2313_set_the_ntp_trusted_key(configuration, ref):
    assert 'ntp trusted-key' in configuration, ref
