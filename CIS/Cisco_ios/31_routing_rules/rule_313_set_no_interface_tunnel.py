from comfy.compliance import medium


@medium(
  name='rule_313_set_no_interface_tunnel',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip int brief | incl Tunnel')
)
def rule_313_set_no_interface_tunnel(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/interface/command/ir-i1.html#GUID-0D6BDFCD-3FBB-"
        "4D26-A274-C1221F8592DF"
    )

    remediation = (f"""
    Remediation: hostname(config)#no interface tunnel {{<em>instance</em>}}

    References: {uri}

    """)

    assert 'Tunnel' in commands.chk_cmd, remediation
