from comfy.compliance import medium


@medium(
  name='rule_126_set_exec_timeout_to_less_than_or_equal_to_10_minutes_for',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run | sec line aux 0')
)
def rule_126_set_exec_timeout_to_less_than_or_equal_to_10_minutes_for(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/D_through_E.html#GUID-768"
        "05E6F-9E89-4457-A9DC-5944C8FE5419"
    )

    remediation = (f"""
    Remediation: hostname(config-line)#exec-timeout <timeout_in_minutes> < timeout_in_seconds>

    References: {uri}

    """)

    assert 'line aux 0' in commands.chk_cmd, remediation
