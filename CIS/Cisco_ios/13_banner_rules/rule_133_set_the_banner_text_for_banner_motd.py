from comfy.compliance import medium


@medium(
  name='rule_133_set_the_banner_text_for_banner_motd',
  platform=['cisco_ios', 'cisco_xe'],
)
def rule_133_set_the_banner_text_for_banner_motd(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/A_through_B.html#GUID-741"
        "6C789-9561-44FC-BB2A-D8D8AFFB77DD"
    )

    remediation = (f"""
    Remediation: hostname(config)#banner motd c
                 Enter TEXT message. End with the character 'c'.
                 <banner-text>
                 c

    References: {uri}

    """)

    assert 'banner motd' in configuration, remediation
