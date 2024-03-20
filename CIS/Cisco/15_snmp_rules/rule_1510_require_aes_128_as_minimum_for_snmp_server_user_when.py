from comfy.compliance import low


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-s5.html#GUID-4EED4031-E723"
    "-4B84-9BBF-610C3CF60E31"
)

remediation = (f"""
    Remediation: hostname(config)#snmp-server user {{user_name}} {{group_name}} v3 auth sha

    References: {uri}

    """)


@low(
  name='rule_1510_require_aes_128_as_minimum_for_snmp_server_user_when',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='show snmp user')
)
def rule_1510_require_aes_128_as_minimum_for_snmp_server_user_when(commands):
    assert 'hostname#show snmp user' in commands.chk_cmd, remediation
