from comfy.compliance import low


@low(
    name='rule_17_ensure_the_cli_login_timeout_is_less_than_or_equal',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show sessions')
)
def rule_17_ensure_the_cli_login_timeout_is_less_than_or_equal(commands, ref):
    assert 'CLI Login Timeout (minutes)............ 0' not in commands.chk_cmd, ref
