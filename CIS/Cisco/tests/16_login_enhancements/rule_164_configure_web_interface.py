from comfy.compliance import low


@low(
  name='rule_164_configure_web_interface',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='Hostname#show ip admission')
)
def rule_164_configure_web_interface(commands):
    uri = (
        ""
        ""
    )

    remediation = (f"""
    Remediation: Hostname#(config)ip admission max-login-attempts {{number}}

    References: {uri}

    """)

    assert 'Hostname#show ip admission' in commands.chk_cmd, remediation
