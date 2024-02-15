from comfy.compliance import low


@low(
  name='rule_2311_set_ntp_authenticate',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_2311_set_ntp_authenticate(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/bsm/command/bsm-cr-nhtml#GUID-8BEBDAF4-6D03-4C"
        "3E-B8D6-6BCBC7D0F324"
    )

    remediation = (f"""
    Remediation: hostname(config)#ntp authenticate

    References: {uri}

    """)

    assert 'ntp' in configuration, remediation
