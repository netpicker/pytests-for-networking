from comfy.compliance import low


@low(
  name='rule_3321_set_authentication_message_digest_for_ospf_area',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run | sec router ospf')
)
def rule_3321_set_authentication_message_digest_for_ospf_area(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_ospf/command/ospf-ahtml#GUID-81D0F753-"
        "D8D5-494E-9A10-B15433CFD445"
    )

    remediation = (f"""
    Remediation: hostname(config-router)#area <<em>ospf_area-id</em>> authentication message -

    References: {uri}

    """)

    assert ' router ospf' in commands.chk_cmd, remediation
