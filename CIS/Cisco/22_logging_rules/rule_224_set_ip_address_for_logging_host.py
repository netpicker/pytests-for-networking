from comfy.compliance import medium


uri = (
    "http://www.cisco.com/en/US/docs/ios/netmgmt/command/reference/nm_09.html#"
    ""
)

remediation = (f"""
    Remediation: hostname(config)#logging host {{syslog_server}}

    References: {uri}

    """)


@medium(
  name='rule_224_set_ip_address_for_logging_host',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh log | incl logging host')
)
def rule_224_set_ip_address_for_logging_host(commands):
    assert ' logging host' in commands.chk_cmd, remediation
