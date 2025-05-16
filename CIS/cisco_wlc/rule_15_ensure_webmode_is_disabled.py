from comfy.compliance import medium


@medium(
    name='rule_15_ensure_webmode_is_disabled',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show network summary')
)
def rule_15_ensure_webmode_is_disabled(commands, ref):
    assert 'Webmode...................................... Disable' in commands.chk_cmd, ref
