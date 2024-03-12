from comfy.compliance import medium


@medium(
  name='rule_131_set_the_banner_text_for_banner_exec',
  platform=['cisco_ios', 'cisco_xe'],
)
def rule_131_set_the_banner_text_for_banner_exec(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/A_through_B.html#GUID-0DE"
        "F5B57-A7D9-4912-861F-E837C82A3881"
    )

    remediation = (f"""
    Remediation: hostname(config)#banner exec c
                 Enter TEXT message. End with the character 'c'. 
                 <banner-text> 
                 c

    References: {uri}

    """)

    assert 'banner exec' in configuration, remediation
