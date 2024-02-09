from comfy.compliance import low


@low(
  name='rule_118_set_aaa_accounting_exec',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_118_set_aaa_accounting_exec(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-ahtml#GUID-0520BCEF-89FB-45"
        "05-A5DF-D7F1389F1BBA"
    )

    remediation = (f"""
    Remediation: hostname(config)#aaa accounting exec {{default | list-name | guarantee-first}}

    References: {uri}

    """)

    assert 'aaaaccounting exec' in configuration, remediation
