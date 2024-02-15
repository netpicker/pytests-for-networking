from comfy.compliance import low


@low(
  name='rule_3319_set_ip_authentication_mode_eigrp',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run int {<em>interface_name</em>} | incl authentication mode')
)
def rule_3319_set_ip_authentication_mode_eigrp(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/command/ire-ihtml#GUID-8D1B0697-"
        "8E96-4D8A-BD20-536956D68506"
    )

    remediation = (f"""
    Remediation: hostname(config-if)#ip authentication mode eigrp {{<em><span>eigrp_as -

    References: {uri}

    """)

    assert 'authentication mode' in commands.chk_cmd, remediation
