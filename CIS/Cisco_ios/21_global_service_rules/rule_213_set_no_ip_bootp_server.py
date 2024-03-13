from comfy.compliance import medium


@medium(
  name='rule_213_set_no_ip_bootp_server',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_213_set_no_ip_bootp_server(configuration):
    remediation = (f"""
    Remediation: hostname(config)#no ip dhcp bootp ignore

    """)

    assert 'no ip dhcp bootp server' in configuration, remediation
