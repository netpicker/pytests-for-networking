from comfy.compliance import medium


@medium(
    name='rule_116_ensure_control_path_rate_limiting_is_enabled',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show advanced rate')
)
def rule_116_ensure_control_path_rate_limiting_is_enabled(commands, ref):
    assert 'Control Path Rate Limiting....................... Enabled' in commands.chk_cmd, ref
