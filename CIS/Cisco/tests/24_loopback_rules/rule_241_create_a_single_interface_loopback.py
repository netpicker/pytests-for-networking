from comfy.compliance import low


@low(
  name='rule_241_create_a_single_interface_loopback',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip int brief | incl Loopback')
)
def rule_241_create_a_single_interface_loopback(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/interface/command/ir-ihtml#GUID-0D6BDFCD-3FBB-"
        "4D26-A274-C1221F8592DF"
    )

    remediation = (f"""
    Remediation: hostname(config-if)#ip address <<em>loopback_ip_address</em>>

    References: {uri}

    """)

    assert ' Loopback' in commands.chk_cmd, remediation
