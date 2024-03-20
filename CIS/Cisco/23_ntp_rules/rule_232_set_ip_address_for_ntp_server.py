from comfy.compliance import medium


uri = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/bsm/command/bsm-cr-book/bsm-cr-nhtml#wp32946"
    "76008"
)

remediation = (f"""
    Remediation: hostname(config)#ntp server {{ntp server vrf [vrf name] ip address}}

    References: {uri}

    """)


@medium(
  name='rule_232_set_ip_address_for_ntp_server',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ntp associations')
)
def rule_232_set_ip_address_for_ntp_server(commands):
    assert 'hostname#sh ntp associations' in commands.chk_cmd, remediation
