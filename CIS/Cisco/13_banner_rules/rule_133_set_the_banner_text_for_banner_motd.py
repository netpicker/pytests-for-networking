from comfy.compliance import medium


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/A_through_B.html#GUID-7416C78"
    "9-9561-44FC-BB2A-D8D8AFFB77DD"
)

remediation = (f"""
    Remediation: hostname(config)#banner motd c

    References: {uri}

    """)


@medium(
  name='rule_133_set_the_banner_text_for_banner_motd',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh running-config | beg banner motd')
)
def rule_133_set_the_banner_text_for_banner_motd(commands):
    assert ' banner motd' in commands.chk_cmd, remediation
