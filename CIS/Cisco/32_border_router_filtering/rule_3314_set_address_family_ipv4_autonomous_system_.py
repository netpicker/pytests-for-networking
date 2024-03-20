from comfy.compliance import low


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/command/ire-ahtml#GUID-C03CFC8A-3CE3"
    "-4CF9-9D65-52990DBD3377"
)

remediation = (f"""
    Remediation: hostname(config-router)#address-family ipv4 autonomous-system {{<em>eigrp_as -

    References: {uri}

    """)


@low(
  name='rule_3314_set_address_family_ipv4_autonomous_system_',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run | sec router eigrp')
)
def rule_3314_set_address_family_ipv4_autonomous_system_(commands):
    assert ' router eigrp' in commands.chk_cmd, remediation
