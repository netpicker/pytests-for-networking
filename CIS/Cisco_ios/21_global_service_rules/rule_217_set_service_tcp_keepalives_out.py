from comfy.compliance import medium


@medium(
  name='rule_217_set_service_tcp_keepalives_out',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_217_set_service_tcp_keepalives_out(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/R_through_setup.html#GUID"
        "-9321ECDC-6284-4BF6-BA4A-9CEEF5F993E5"
    )

    remediation = (f"""
    Remediation: hostname(config)#service tcp-keepalives-out

    References: {uri}

    """)

    assert 'service tcp-keepalives-out' in configuration, remediation
