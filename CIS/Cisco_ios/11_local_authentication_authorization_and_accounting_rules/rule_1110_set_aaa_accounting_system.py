from comfy.compliance import low


@low(
  name='rule_1110_set_aaa_accounting_system',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_1110_set_aaa_accounting_system(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a1.html#GUID-0520BCEF-89FB-45"
        "05-A5DF-D7F1389F1BBA"
    )

    remediation = (f"""
    Remediation: hostname(config)#aaa accounting system [[default | list-name | guarantee -
                 first] [start-stop | stop-only | none] [radius | group group-name]

    References: {uri}

    """)

    assert 'aaa accounting system' in configuration, remediation
