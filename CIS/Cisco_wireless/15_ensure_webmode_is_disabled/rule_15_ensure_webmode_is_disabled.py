from comfy.compliance import medium


@medium(
  name='rule_15_ensure_webmode_is_disabled',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show network summary')
)
def rule_15_ensure_webmode_is_disabled(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show network summary' in commands.chk_cmd, remediation
