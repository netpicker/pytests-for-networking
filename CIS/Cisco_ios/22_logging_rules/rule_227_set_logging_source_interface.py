from comfy.compliance import medium


@medium(
  name='rule_227_set_logging_source_interface',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_227_set_logging_source_interface(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios/netmgmt/command/reference/nm_09.html#"
        "wp1095099"
    )

    remediation = (f"""
    Remediation: hostname(config)#logging source-interface loopback
                 {<em>loopback_interface_number</em>}
    References: {uri}

    """)

    assert 'logging source' in configuration, remediation
