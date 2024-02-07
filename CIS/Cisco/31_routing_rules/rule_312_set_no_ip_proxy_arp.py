from comfy.compliance import low


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/ipaddr/command/ipaddr-i4.html#GUID-AEB7DDCB-7B3D-4"
    "036-ACF0-0A0250F3002E"
)

remediation = (f"""
    Remediation: hostname(config)#interface {{interface}}

    References: {uri}

    """)


@low(
  name='rule_312_set_no_ip_proxy_arp',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip int {<em>interface</em>} | incl proxy-arp')
)
def rule_312_set_no_ip_proxy_arp(commands):
    assert ' proxy-arp' in commands.chk_cmd, remediation
