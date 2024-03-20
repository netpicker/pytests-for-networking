from comfy.compliance import medium


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/D_through_E.html#GUID-76805E6"
    "F-9E89-4457-A9DC-5944C8FE5419"
)

remediation = (f"""
    Remediation: hostname(config-line)#exec-timeout <timeout_in_minutes> <timeout_in_seconds>

    References: {uri}

    """)


@medium(
  name='rule_127_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run | sec line con 0')
)
def rule_127_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line(commands):
    assert ' line con 0' in commands.chk_cmd, remediation
