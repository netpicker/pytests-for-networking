from comfy.compliance import low

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/bsm/command/bsm-cr-nhtml#GUID-8BEBDAF4-6D03-4C3E-B"
    "8D6-6BCBC7D0F324"
)

remediation = (f"""
    Remediation: hostname(config)#ntp authenticate

    References: {uri}

    """)


@low(
  name='rule_2311_set_ntp_authenticate',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_2311_set_ntp_authenticate(configuration):
    assert 'ntp' in configuration, remediation
