from comfy.compliance import medium

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/R_through_setup.html#GUID-932"
    "1ECDC-6284-4BF6-BA4A-9CEEF5F993E5"
)

remediation = (f"""
    Remediation: hostname(config)#service tcp-keepalives-out

    References: {uri}

    """)


@medium(
  name='rule_217_set_service_tcp_keepalives_out',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_217_set_service_tcp_keepalives_out(configuration):
    assert 'service tcp' in configuration, remediation
