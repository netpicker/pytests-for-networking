from comfy.compliance import medium


@medium(
  name='rule_123_set_no_exec_for_line_aux_0',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='show line aux 0 | incl exec')
)
def rule_123_set_no_exec_for_line_aux_0(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/D_through_E.html#GUID-429"
        "A2B8C-FC26-49C4-94C4-0FD99C32EC34"
    )

    remediation = (f"""
    Remediation: hostname(config-line)#no exec

    References: {uri}

    """)

    assert ' exec' in commands.chk_cmd, remediation
