from comfy.compliance import medium


@medium(
    name='rule_21115_set_maximum_value_for_ip_ssh_authentication_retries',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh ip ssh')
)
def rule_21115_set_maximum_value_for_ip_ssh_authentication_retries(commands, ref):
    assert 'Authentication retries: 3' in commands.chk_cmd, ref
