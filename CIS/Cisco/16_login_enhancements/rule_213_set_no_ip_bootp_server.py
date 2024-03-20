from comfy.compliance import medium

uri = (
    ""
    ""
)

remediation = (f"""
    Remediation: hostname(config)#ip dhcp bootp ignore

    References: {uri}

    """)


@medium(
  name='rule_213_set_no_ip_bootp_server',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_213_set_no_ip_bootp_server(configuration):
    assert 'bootp' in configuration, remediation
