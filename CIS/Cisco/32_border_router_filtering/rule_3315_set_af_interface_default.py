from comfy.compliance import low


@low(
  name='rule_3315_set_af_interface_default',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run | sec router eigrp')
)
def rule_3315_set_af_interface_default(commands):
    uri = (
        "3.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/command/ire-ahtml#GUID-DC0EF1D"
        "3-DFD4-45DF-A553-FA432A3E7233"
    )

    remediation = (f"""
    Remediation: hostname(config-router-af)#af-interface default

    References: {uri}

    """)

    assert 'router eigrp' in commands.chk_cmd, remediation
