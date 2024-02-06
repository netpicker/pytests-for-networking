from comfy.compliance import low


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_pi/command/iri-cr-ahtml#GUID-D7A8DC18-2E16"
    "-4EA5-8762-8B68B94CC43E"
)

remediation = (f"""
    Remediation: hostname(config-keychain-key)#key-string <<em>key-string</em>>

    References: {uri}

    """)


@low(
  name='rule_3313_set_key_string',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh  run | sec key chain')
)
def rule_3313_set_key_string(commands):
    assert ' key chain' in commands.chk_cmd, remediation
