from comfy.compliance import medium


@medium(
  name='rule_232_set_ip_address_for_ntp_server',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ntp associations')
)
def rule_232_set_ip_address_for_ntp_server(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/bsm/command/bsm-cr-n1.html#GUID-255145EB-"
        "D656-43F0-B361-D9CBCC794112"
        "\n"
        "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/bsm/command/bsm-cr-book/bsm-cr-n1.html#wp3"
        "294676008"
    )

    remediation = (f"""
    Remediation: hostname(config)#ntp server {ntp-server_ip_address}
                 or
                 hostname(config)#ntp server {{ntp server vrf [vrf name] ip address}}

    References: {uri}

    """)

    assert '*~' in commands.chk_cmd, remediation
