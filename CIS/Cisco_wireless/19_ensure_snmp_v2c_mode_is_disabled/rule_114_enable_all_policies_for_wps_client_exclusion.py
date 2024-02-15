from comfy.compliance import low


@low(
  name='rule_114_enable_all_policies_for_wps_client_exclusion',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show wps summary')
)
def rule_114_enable_all_policies_for_wps_client_exclusion(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show wps summary' in commands.chk_cmd, remediation
