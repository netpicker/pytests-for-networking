from comfy.compliance import medium


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-ahtml#GUID-9EA733A3-1788-4882-B"
    "8C3-AB0A2949120C"
)

remediation = (f"""
    Remediation: hostname(config)#access-list deny any log

    References: {uri}

    """)


@medium(
  name='rule_156_create_an_access_list_for_use_with_snmp',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip access-list <<em>snmp_acl_number</em>>')
)
def rule_156_create_an_access_list_for_use_with_snmp(commands):
    assert 'hostname#sh ip access-list <<em>snmp_acl_number</em>>' in commands.chk_cmd, remediation
