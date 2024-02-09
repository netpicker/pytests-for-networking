from comfy.compliance import medium


@medium(
  name='rule_213_set_no_ip_bootp_server',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_213_set_no_ip_bootp_server(configuration):
    uri = (
        ""
        ""
    )

    remediation = (f"""
    Remediation: hostname(config)#ip dhcp bootp ignore

    References: {uri}

    """)

    assert 'bootp' in configuration, remediation
