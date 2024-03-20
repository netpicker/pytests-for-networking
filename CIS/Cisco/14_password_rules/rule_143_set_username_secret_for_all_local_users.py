from comfy.compliance import medium

uri = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9600/software/releas"
    ""
)

remediation = (f"""
    Remediation: hostname(config)#username {{{{em}}LOCAL_USERNAME{{/em}}}} secret

    References: {uri}

    """)


@medium(
  name='rule_143_set_username_secret_for_all_local_users',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_143_set_username_secret_for_all_local_users(configuration):
    assert 'username' in configuration, remediation
