from comfy.compliance import low


@low(
  name='rule_3316_set_authentication_key_chain',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run | sec router eigrp')
)
def rule_3316_set_authentication_key_chain(commands):
    uri = (
        "3.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/command/ire-ahtml#GUID-6B6ED6A"
        "3-1AAA-4EFA-B6B8-9BF11EEC37A0"
    )

    remediation = (f"""
    Remediation: hostname(config-router-af-interface)#authentication key-chain {{eigrp_key -

    References: {uri}

    """)

    assert ' router eigrp' in commands.chk_cmd, remediation
