from comfy.compliance import medium


@medium(
  name='rule_21111_set_the_hostname',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_21111_set_the_hostname(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/F_through_K.html#GUID-F33"
        "49988-EC16-484A-BE81-4C40110E6625"
    )

    remediation = (f"""
    Remediation: hostname(config)#hostname [router_name]

    References: {uri}

    """)

    assert 'hostname' in configuration, remediation
