from comfy.compliance import medium


@medium(
  name='rule_21114_set_seconds_for_ip_ssh_timeout_for_60_seconds_or_less',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip ssh')
)
def rule_21114_set_seconds_for_ip_ssh_timeout_for_60_seconds_or_less(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-i3.html#GUID-5BAC7A2B-0A25-"
        "400F-AEE9-C22AE08513C6"
    )

    remediation = (f"""
    Remediation: hostname(config)#ip ssh time-out [<em>60</em>]

    References: {uri}

    """)

    assert 'Authentication timeout: 60 secs;' in commands.chk_cmd, remediation
