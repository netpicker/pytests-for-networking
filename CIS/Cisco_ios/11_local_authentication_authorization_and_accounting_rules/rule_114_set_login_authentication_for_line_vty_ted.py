@medium(
    name='rule_114_set_login_authentication_for_line_vty_ted',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_con='show running-config | sec line con',chk_vty='show running-config | sec line vty')
)
def rule_114_set_login_authentication_for_line_vty_ted(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-k1.html#GUID-297BDF33-4841-44"
        "1C-83F3-4DA51C3C7284"
    )

    remediation = (f"""
    Remediation: hostname(config-line)#login authentication {{default | aaa_list_name}}

    References: {uri}

    """)
    assert 'login authentication' in commands.chk_con, remediation
    assert 'login authentication' in commands.chk_vty, remediation
