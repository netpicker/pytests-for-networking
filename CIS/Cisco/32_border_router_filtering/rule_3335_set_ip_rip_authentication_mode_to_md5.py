from comfy.compliance import low


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_rip/command/irr-cr-rip.html#GUID-47536344-"
    "60DC-4D30-9E03-94FF336332C7"
)

remediation = (f"""
    Remediation: hostname(config-if)#ip rip authentication mode md5

    References: {uri}

    """)


@low(
  name='rule_3335_set_ip_rip_authentication_mode_to_md5',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run int <<em>interface</em>>')
)
def rule_3335_set_ip_rip_authentication_mode_to_md5(commands):
    assert 'hostname#sh run int <<em>interface</em>>' in commands.chk_cmd, remediation
