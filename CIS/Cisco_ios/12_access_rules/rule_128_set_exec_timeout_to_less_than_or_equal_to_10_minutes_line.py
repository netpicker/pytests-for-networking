from comfy.compliance import medium


@medium(
  name='rule_128_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh line vty | begin timeout')
)
def rule_128_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line(commands):
    uri = (
        "https://www.cisco.com/c/en/us/td/docs/switches/datacenter/mds9000/sw/comma"
        "nd/b_cisco_mds_9000_cr_book/l_commands.html#wp3716128869"
    )

    remediation = (f"""
    Remediation: hostname(config)#line vty {line_number} [ending_line_number]
                 hostname(config-line)#exec-timeout <timeout_in_minutes> <timeout_in_seconds>

    References: {uri}

    """)

    assert 'exec-timeout 10 0' in commands.chk_cmd, remediation
