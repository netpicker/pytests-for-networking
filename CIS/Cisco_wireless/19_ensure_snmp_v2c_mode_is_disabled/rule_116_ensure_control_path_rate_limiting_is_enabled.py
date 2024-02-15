from comfy.compliance import medium


@medium(
  name='rule_116_ensure_control_path_rate_limiting_is_enabled',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show advanced rate')
)
def rule_116_ensure_control_path_rate_limiting_is_enabled(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show advanced rate' in commands.chk_cmd, remediation
