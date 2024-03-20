from comfy.compliance import medium

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/ipaddr/command/ipaddr-i4.html#GUID-C7F971DD-358F-4"
    "B43-9F3E-244F5D4A3A93"
)

remediation = (f"""
    Remediation: hostname(config)#no ip source-route

    References: {uri}

    """)


@medium(
  name='rule_311_set_no_ip_source_route',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_311_set_no_ip_source_route(configuration):
    assert 'ip source-route' in configuration, remediation
