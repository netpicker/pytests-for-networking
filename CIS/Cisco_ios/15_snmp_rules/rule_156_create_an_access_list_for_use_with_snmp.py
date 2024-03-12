from comfy.compliance import medium


@medium(
  name='rule_156_create_an_access_list_for_use_with_snmp',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip access-list <<em>snmp_acl_number</em>>')
)
def rule_156_create_an_access_list_for_use_with_snmp(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a2.html#GUID-9EA733A3-1788-48"
        "82-B8C3-AB0A2949120C"
    )

    remediation = (f"""
    Remediation: hostname(config)#access-list <<em>snmp_acl_number</em>> permit <<em>snmp_access-list</em>>
                 hostname(config)#access-list deny any log

    References: {uri}

    """)

    assert 'access-list deny any log' in commands.chk_cmd, remediation
