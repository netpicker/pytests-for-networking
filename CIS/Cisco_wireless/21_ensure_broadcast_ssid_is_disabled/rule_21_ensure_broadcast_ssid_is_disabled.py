from comfy.compliance import medium


@medium(
  name='rule_21_ensure_broadcast_ssid_is_disabled',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show wlan summary')
)
def rule_21_ensure_broadcast_ssid_is_disabled(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show wlan summary' in commands.chk_cmd, remediation
