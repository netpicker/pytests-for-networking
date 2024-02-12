from comfy.compliance import low


@low(
  name='rule_321_set_ip_access_list_extended_to_forbid_privat_e_source',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip access-list {<em>name | number</em>}')
)
def rule_321_set_ip_access_list_extended_to_forbid_privat_e_source(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-ihtml#GUID-BD76E065-8EAC-4B"
        "32-AF25-04BA94DD2B11"
    )

    remediation = (f"""
    Remediation: hostname(config-if)#access-group <<em>access-list</em>> in

    References: {uri}

    """)

    assert 'hostname#sh ip access-list {<em>name | number</em>}' in commands.chk_cmd, remediation
