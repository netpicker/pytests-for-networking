from comfy.compliance import medium


@medium(
  name='rule_212_set_no_cdp_run',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='show  cdp')
)
def rule_212_set_no_cdp_run(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/cdp/command/cdp-cr-a1.html#GUID-E006FAC8-417E-4C"
        "3F-B732-4D47B0447750"
    )

    remediation = (f"""
    Remediation: hostname(config)#no cdp run

    References: {uri}

    """)

    assert 'CDP is not enabled' in commands.chk_cmd, remediation
