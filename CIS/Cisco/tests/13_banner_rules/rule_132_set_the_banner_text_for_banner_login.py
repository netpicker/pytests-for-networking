from comfy.compliance import medium


@medium(
  name='rule_132_set_the_banner_text_for_banner_login',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='show running-config | beg banner login')
)
def rule_132_set_the_banner_text_for_banner_login(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/A_through_B.html#GUID-FF0"
        "B6890-85B8-4B6A-90DD-1B7140C5D22F"
    )

    remediation = (f"""
    Remediation: hostname(config)#banner login c

    References: {uri}

    """)

    assert ' banner login' in commands.chk_cmd, remediation
