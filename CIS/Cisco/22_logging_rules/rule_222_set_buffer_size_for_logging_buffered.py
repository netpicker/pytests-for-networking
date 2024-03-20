from comfy.compliance import medium

uri = (
    "http://www.cisco.com/en/US/docs/ios/netmgmt/command/reference/nm_09.html#"
    ""
)

remediation = (f"""
    Remediation: hostname(config)#logging buffered [<em>log_buffer_size</em>]

    References: {uri}

    """)


@medium(
  name='rule_222_set_buffer_size_for_logging_buffered',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_222_set_buffer_size_for_logging_buffered(configuration):
    assert 'logging buffered' in configuration, remediation
