from comfy.compliance import low


uri = (
    ""
    ""
)

remediation = (f"""
    Remediation: Hostname#(config)ip admission max-login-attempts {{number}}

    References: {uri}

    """)


@low(
  name='rule_164_configure_web_interface',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='Hostname#show ip admission')
)
def rule_164_configure_web_interface(commands):
    assert 'Hostname#show ip admission' in commands.chk_cmd, remediation
