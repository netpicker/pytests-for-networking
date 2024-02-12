from comfy.compliance import medium


@medium(
  name='rule_13_delete_the_user_name_admin',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show mgmtuser')
)
def rule_13_delete_the_user_name_admin(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show mgmtuser' in commands.chk_cmd, remediation
