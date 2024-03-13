from comfy.compliance import medium


@medium(
  name='rule_216_set_service_tcp_keepalives_in',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_216_set_service_tcp_keepalives_in(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/R_through_setup.html#GUID"
        "-1489ABA3-2428-4A64-B252-296A035DB85E"
    )

    remediation = (f"""
    Remediation: hostname(config)#serv ice tcp-keepalives-in

    References: {uri}

    """)

    assert 'service tcp-keepalives-in' in configuration, remediation
