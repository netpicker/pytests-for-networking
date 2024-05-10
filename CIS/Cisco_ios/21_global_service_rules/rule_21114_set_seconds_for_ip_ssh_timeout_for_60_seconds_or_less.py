from comfy.compliance import medium


@medium(
    name='rule_21114_set_seconds_for_ip_ssh_timeout_for_60_seconds_or_less',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh ip ssh')
)
def rule_21114_set_seconds_for_ip_ssh_timeout_for_60_seconds_or_less(commands, ref):
    assert 'Authentication timeout: 60 secs;' in commands.chk_cmd, ref
