from comfy.compliance import low


@low(
  name='rule_119_set_aaa_accounting_network',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_119_set_aaa_accounting_network(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a1.html#GUID-0520BCEF-89FB-45"
        "05-A5DF-D7F1389F1BBA"
    )

    remediation = (f"""
    Remediation: hostname(config)#aaa accounting network [[default | list-name | guarantee -
                 first] [start-stop | stop-only | none] [radius | group group-name]

    References: {uri}

    """)

    assert 'aaa accounting network' in configuration, remediation
