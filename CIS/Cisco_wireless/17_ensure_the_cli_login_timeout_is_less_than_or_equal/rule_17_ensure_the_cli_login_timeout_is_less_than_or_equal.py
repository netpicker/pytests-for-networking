from comfy.compliance import low


@low(
  name='rule_17_ensure_the_cli_login_timeout_is_less_than_or_equal',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show sessions')
)
def rule_17_ensure_the_cli_login_timeout_is_less_than_or_equal(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show sessions' in commands.chk_cmd, remediation
