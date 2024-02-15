from comfy.compliance import medium


@medium(
  name='rule_214_set_no_service_dhcp',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_214_set_no_service_dhcp(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/ipaddr/command/ipaddr-rhtml#GUID-1516B259-AA28"
        "-4839-B968-8DDBF0B382F6"
    )

    remediation = (f"""
    Remediation: hostname(config)#<strong>no service dhcp</strong>

    References: {uri}

    """)

    assert 'dhcp' in configuration, remediation
