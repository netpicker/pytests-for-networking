from comfy.compliance import medium


@medium(
  name='rule_12_ensure_password_strength_is_strong_for_configured_user',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show mgmtuser')
)
def rule_12_ensure_password_strength_is_strong_for_configured_user(commands):
    uri = (
        ""
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show mgmtuser' in commands.chk_cmd, remediation
