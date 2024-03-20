from comfy.compliance import medium

uri = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9600/software/releas"
    ""
)

remediation = (f"""
    Remediation: hostname(config)#enable secret 9 {{ENABLE_SECRET_PASSWORD}}

    References: {uri}

    """)


@medium(
  name='rule_141_set_password_for_enable_secret',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_141_set_password_for_enable_secret(configuration):
    assert 'enable secret' in configuration, remediation
