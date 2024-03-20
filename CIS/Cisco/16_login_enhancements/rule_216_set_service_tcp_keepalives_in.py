from comfy.compliance import medium

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/R_through_setup.html#GUID-148"
    "9ABA3-2428-4A64-B252-296A035DB85E"
)

remediation = (f"""
    Remediation: hostname(config)#serv ice tcp-keepalives-in

    References: {uri}

    """)


@medium(
  name='rule_216_set_service_tcp_keepalives_in',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_216_set_service_tcp_keepalives_in(configuration):
    assert 'service tcp' in configuration, remediation
