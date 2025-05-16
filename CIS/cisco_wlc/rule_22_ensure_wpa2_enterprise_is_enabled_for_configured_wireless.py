from comfy.compliance import medium


@medium(
    name='rule_22_ensure_wpa2_enterprise_is_enabled_for_configured_wireless',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show wlan <WLAN ID>')
)
def rule_22_ensure_wpa2_enterprise_is_enabled_for_configured_wireless(commands, ref):
    assert 'Disable' not in commands.chk_cmd, ref
