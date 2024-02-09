from comfy.compliance import medium


@medium(
  name='rule_215_set_no_ip_identd',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_215_set_no_ip_identd(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/solutions/Enterprise/Security/Baseline_Securit"
        ""
    )

    remediation = (f"""
    Remediation: hostname(config)#no ip identd

    References: {uri}

    """)

    assert 'identd' in configuration, remediation
