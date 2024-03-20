from comfy.compliance import medium


uri = (
    "https://www.cisco.com/c/en/us/td/docs/switches/datacenter/mds9000/sw/comma"
    ""
)

remediation = (f"""
    Remediation: hostname(config-line)#exec-timeout <<span>timeout_in_minutes>

    References: {uri}

    """)


@medium(
  name='rule_128_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh line vty <tty_line_number> | begin Timeout')
)
def rule_128_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line(commands):
    assert 'in Timeout' in commands.chk_cmd, remediation
