from comfy.compliance import medium


@medium(
    name='rule_14_ensure_telnet_is_disabled',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show network summary')
)
def rule_14_ensure_telnet_is_disabled(commands, ref):
    assert 'Telnet...................................... Disable' in commands.chk_cmd, ref
