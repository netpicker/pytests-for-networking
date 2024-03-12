from comfy.compliance import medium


@medium(
  name='rule_21115_set_maximum_value_for_ip_ssh_authentication_retries',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip ssh')
)
def rule_21115_set_maximum_value_for_ip_ssh_authentication_retries(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-i3.html#GUID-5BAC7A2B-0A25-"
        "400F-AEE9-C22AE08513C6"
    )

    remediation = (f"""
    Remediation: hostname(config)#ip ssh authentication-retries [<em>3</em>]

    References: {uri}

    """)

    assert 'Authentication retries: 3' in commands.chk_cmd, remediation
