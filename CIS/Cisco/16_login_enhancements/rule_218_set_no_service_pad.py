from comfy.compliance import medium

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/wan/command/wan-shtml#GUID-C5497B77-3FD4-4D2F-AB08"
    "-1317D5F5473B"
)

remediation = (f"""
    Remediation: hostname(config)#no service pad

    References: {uri}

    """)


@medium(
  name='rule_218_set_no_service_pad',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_218_set_no_service_pad(configuration):
    assert 'service pad' in configuration, remediation
