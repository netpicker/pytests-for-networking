from comfy.compliance import medium

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/F_through_K.html#GUID-F334998"
    "8-EC16-484A-BE81-4C40110E6625"
)

remediation = (f"""
    Remediation: hostname(config)#hostname {{<em>router_name</em>}}

    References: {uri}

    """)


@medium(
  name='rule_21111_set_the_hostname',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_21111_set_the_hostname(configuration):
    assert 'hostname' in configuration, remediation
