from comfy.compliance import low


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/command/ire-ihtml#GUID-0B344B46-5E8E"
    "-4FE2-A3E0-D92410CE5E91"
)

remediation = (f"""
    Remediation: hostname(config-if)#ip authentication key-chain eigrp {{<em>eigrp_as -

    References: {uri}

    """)


@low(
  name='rule_3318_set_ip_authentication_key_chain_eigrp_utomated',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run int {<em>interface_name</em>} | incl key-chain')
)
def rule_3318_set_ip_authentication_key_chain_eigrp_utomated(commands):
    assert ' key-chain' in commands.chk_cmd, remediation
