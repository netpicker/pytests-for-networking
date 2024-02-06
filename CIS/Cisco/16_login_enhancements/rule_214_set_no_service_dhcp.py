from comfy.compliance import medium

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/ipaddr/command/ipaddr-rhtml#GUID-1516B259-AA28-483"
    "9-B968-8DDBF0B382F6"
)

remediation = (f"""
    Remediation: hostname(config)#<strong>no service dhcp</strong>

    References: {uri}

    """)


@medium(
  name='rule_214_set_no_service_dhcp',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_214_set_no_service_dhcp(configuration):
    assert 'dhcp' in configuration, remediation
