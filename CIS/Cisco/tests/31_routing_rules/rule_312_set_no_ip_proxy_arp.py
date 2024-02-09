from comfy.compliance import low


@low(
  name='rule_312_set_no_ip_proxy_arp',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip int {<em>interface</em>} | incl proxy-arp')
)
def rule_312_set_no_ip_proxy_arp(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/ipaddr/command/ipaddr-i4.html#GUID-AEB7DDCB-7B"
        "3D-4036-ACF0-0A0250F3002E"
    )

    remediation = (f"""
    Remediation: hostname(config)#interface {{interface}}

    References: {uri}

    """)

    assert ' proxy-arp' in commands.chk_cmd, remediation
