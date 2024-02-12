from comfy.compliance import medium


@medium(
  name='rule_113_ensure_signature_processing_is_enabled',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show wps summary')
)
def rule_113_ensure_signature_processing_is_enabled(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show wps summary' in commands.chk_cmd, remediation
