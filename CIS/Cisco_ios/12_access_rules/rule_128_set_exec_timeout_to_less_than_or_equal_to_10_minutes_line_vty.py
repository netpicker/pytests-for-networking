from comfy.compliance import medium


@medium(
    name='rule_128_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh line vty | begin timeout')
)
def rule_128_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line(commands, ref):
    assert 'exec-timeout 10 0' in commands.chk_cmd, ref
