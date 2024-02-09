from comfy.compliance import low


@low(
  name='rule_322_set_inbound_ip_access_group_on_the_external_interface',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run | sec interface {<em>external_interface</em>}')
)
def rule_322_set_inbound_ip_access_group_on_the_external_interface(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-ihtml#GUID-D9FE7E44-7831-4C"
        "64-ACB8-840811A0C993"
    )

    remediation = (f"""
    Remediation: hostname(config-if)#ip access-group {{name | number}} in

    References: {uri}

    """)

    assert ' interface {<em>external_interface</em>}' in commands.chk_cmd, remediation
