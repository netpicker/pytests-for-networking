from comfy.compliance import medium

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-ahtml#GUID-3DB1CC8A-4A98-400B-A"
    "906-C42F265C7EA2"
)

remediation = (f"""
    Remediation: hostname(config)#aaa authentication login {{default | aaa_list_name}} [passwd -

    References: {uri}

    """)


@medium(
  name='rule_112_enable_aaa_authentication_login',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_112_enable_aaa_authentication_login(configuration):
    assert 'aaa authentication login' in configuration, remediation
