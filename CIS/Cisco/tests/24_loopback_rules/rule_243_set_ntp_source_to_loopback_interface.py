from comfy.compliance import low


@low(
  name='rule_243_set_ntp_source_to_loopback_interface',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_243_set_ntp_source_to_loopback_interface(configuration):
    uri = (
        ""
        ""
    )

    remediation = (f"""
    Remediation: hostname(config)#ntp source loopback {{<em> loopback_interface_number}}</em>

    References: {uri}

    """)

    assert 'ntp source' in configuration, remediation
