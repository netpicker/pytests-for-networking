from comfy.compliance import medium


@medium(
  name='rule_313_set_no_interface_tunnel',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip int brief | incl tunnel')
)
def rule_313_set_no_interface_tunnel(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/interface/command/ir-ihtml#GUID-0D6BDFCD-3FBB-"
        "4D26-A274-C1221F8592DF"
    )

    remediation = (f"""
    Remediation: hostname(config)#no interface tunnel {{<em>instance</em>}}

    References: {uri}

    """)

    assert ' tunnel' in commands.chk_cmd, remediation
