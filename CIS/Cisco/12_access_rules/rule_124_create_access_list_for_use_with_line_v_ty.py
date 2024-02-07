from comfy.compliance import medium


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-ahtml#GUID-9EA733A3-1788-4882-B"
    "8C3-AB0A2949120C"
)

remediation = (f"""
    Remediation: hostname(config)#deny ip any any log

    References: {uri}

    """)


@medium(
  name='rule_124_create_access_list_for_use_with_line_v_ty',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip access-list <vty_acl_number>')
)
def rule_124_create_access_list_for_use_with_line_v_ty(commands):
    assert 'hostname#sh ip access-list <vty_acl_number>' in commands.chk_cmd, remediation
