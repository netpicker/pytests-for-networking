from comfy.compliance import medium


@medium(
  name='rule_113_enable_aaa_authentication_enable_default',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_113_enable_aaa_authentication_enable_default(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a1.html#GUID-4171D649-2973-47"
        "07-95F3-9D96971893D0"
    )

    remediation = (f"""
    Remediation: hostname(config)#aaa authentication enable default {{method1}} enable

    References: {uri}

    """)

    assert 'aaa authentication enable' in configuration, remediation
