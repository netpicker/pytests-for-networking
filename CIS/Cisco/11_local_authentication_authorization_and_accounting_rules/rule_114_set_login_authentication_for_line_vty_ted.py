from comfy.compliance import medium


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-khtml#GUID-297BDF33-4841-441C-8"
    "3F3-4DA51C3C7284"
)

remediation = (f"""
    Remediation: hostname(config-line)#login authentication {{default | aaa_list_name}}

    References: {uri}

    """)


@medium(
  name='rule_114_set_login_authentication_for_line_vty_ted',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='show running-config | sec line | incl l ogin authentication')
)
def rule_114_set_login_authentication_for_line_vty_ted(commands):
    assert ' l ogin authentication' in commands.chk_cmd, remediation
