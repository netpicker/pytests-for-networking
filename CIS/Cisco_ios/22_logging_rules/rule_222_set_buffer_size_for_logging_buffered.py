from comfy.compliance import medium


@medium(
  name='rule_222_set_buffer_size_for_logging_buffered',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_222_set_buffer_size_for_logging_buffered(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios/netmgmt/command/reference/nm_09.html#"
        "wp1015177"
    )

    remediation = (f"""
    Remediation: hostname(config)#logging buffered [<em>log_buffer_size</em>]

    References: {uri}

    """)

    assert 'logging buffered' in configuration, remediation
