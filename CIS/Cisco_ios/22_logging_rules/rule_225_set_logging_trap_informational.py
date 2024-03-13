from comfy.compliance import medium


@medium(
  name='rule_225_set_logging_trap_informational',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh log | incl logging trap')
)
def rule_225_set_logging_trap_informational(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios/netmgmt/command/reference/nm_09.html#"
        "wp1015177"
    )

    remediation = (f"""
    Remediation: hostname(config)#logging trap informational

    References: {uri}

    """)

    assert 'logging trap informational' in commands.chk_cmd, remediation
