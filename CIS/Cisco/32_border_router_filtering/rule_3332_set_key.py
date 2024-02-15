from comfy.compliance import low


@low(
  name='rule_3332_set_key',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run | sec key chain')
)
def rule_3332_set_key(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_pi/command/iri-cr-ahtml#GUID-3F31B2E0-"
        "0E4B-4F49-A4A8-8ADA1CA0D73F"
    )

    remediation = (f"""
    Remediation: hostname(config-keychain)#key {{<em>key-number</em>}}

    References: {uri}

    """)

    assert 'key chain' in commands.chk_cmd, remediation
