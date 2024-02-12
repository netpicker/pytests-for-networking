from comfy.compliance import low


@low(
  name='rule_3334_set_ip_rip_authentication_key_chain',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run int {<em>interface_name</em>}')
)
def rule_3334_set_ip_rip_authentication_key_chain(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_rip/command/irr-cr-rip.html#GUID-C1C84"
        "D0D-4BD0-4910-911A-ADAB458D0A84"
    )

    remediation = (f"""
    Remediation: hostname(config-if)#ip rip authentication key-chain {{<em>rip_key -

    References: {uri}

    """)

    assert 'hostname#sh run int {<em>interface_name</em>}' in commands.chk_cmd, remediation
