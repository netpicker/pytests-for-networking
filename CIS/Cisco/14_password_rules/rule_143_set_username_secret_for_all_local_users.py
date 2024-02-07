from comfy.compliance import medium


@medium(
  name='rule_143_set_username_secret_for_all_local_users',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_143_set_username_secret_for_all_local_users(configuration):
    uri = (
        "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9600/software/releas"
        ""
    )

    remediation = (f"""
    Remediation: hostname(config)#username {{{{em}}LOCAL_USERNAME{{/em}}}} secret

    References: {uri}

    """)

    assert 'username' in configuration, remediation
