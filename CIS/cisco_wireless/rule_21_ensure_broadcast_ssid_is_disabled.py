from comfy.compliance import medium


@medium(
    name='rule_21_ensure_broadcast_ssid_is_disabled',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show wlan summary')
)
def rule_21_ensure_broadcast_ssid_is_disabled(commands, ref):
    assert 'Broadcast SSID................................... Disabled' in commands.chk_cmd, ref
