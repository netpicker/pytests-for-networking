from comfy.compliance import medium


@medium(
    name='rule_112_enable_aaa_authentication_login',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_112_enable_aaa_authentication_login(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a1.html#GUID-3DB1CC8A-4A98-40"
        "0B-A906-C42F265C7EA2"
    )

    remediation = (f"""
    Remediation: hostname(config)#aaa authentication login {{default | aaa_list_name}} [passwd -
 expiry] [method1] [method2]

    References: {uri}

    """)

    assert 'aaa authentication login' in configuration, remediation
