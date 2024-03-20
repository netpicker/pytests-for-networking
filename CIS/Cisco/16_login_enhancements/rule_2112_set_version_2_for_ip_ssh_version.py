from comfy.compliance import medium


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-i3.html#GUID-170AECF1-4B5B-462A"
    "-8CC8-999DEDC45C21"
)

remediation = (f"""
    Remediation: hostname(config)#ip ssh version 2

    References: {uri}

    """)


@medium(
  name='rule_2112_set_version_2_for_ip_ssh_version',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip ssh')
)
def rule_2112_set_version_2_for_ip_ssh_version(commands):
    assert 'hostname#sh ip ssh' in commands.chk_cmd, remediation
