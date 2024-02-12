from comfy.compliance import medium


@medium(
  name='rule_22_ensure_wpa2_enterprise_is_enabled_for_configured_wireless',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show wlan <WLAN ID>')
)
def rule_22_ensure_wpa2_enterprise_is_enabled_for_configured_wireless(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show wlan <WLAN ID>' in commands.chk_cmd, remediation
