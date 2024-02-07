from comfy.compliance import medium


@medium(
  name='rule_131_set_the_banner_text_for_banner_exec',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh running-config | beg banner exec')
)
def rule_131_set_the_banner_text_for_banner_exec(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/A_through_B.html#GUID-0DE"
        "F5B57-A7D9-4912-861F-E837C82A3881"
    )

    remediation = (f"""
    Remediation: hostname(config)#banner exec c

    References: {uri}

    """)

    assert ' banner exec' in commands.chk_cmd, remediation
