from comfy.compliance import medium


@medium(
  name='rule_115_set_login_authentication_for_ip_http_ed',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_115_set_login_authentication_for_ip_http_ed(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-khtml#GUID-297BDF33-4841-44"
        "1C-83F3-4DA51C3C7284"
    )

    remediation = (f"""
    Remediation: hostname#(config)ip http authentication {{default | _aa a_list_name_}}

    References: {uri}

    """)

    assert 'ip http authentication' in configuration, remediation
