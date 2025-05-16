from comfy.compliance import medium


@medium(
    name='rule_12_ensure_password_strength_is_strong_for_configured_user_names',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show mgmtuser')
)
def rule_12_ensure_password_strength_is_strong_for_configured_user_names(commands, ref):
    assert 'Strong' in commands.chk_cmd, ref
