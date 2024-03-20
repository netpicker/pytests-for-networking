from comfy.compliance import low

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/bsm/command/bsm-cr-nhtml#GUID-89CA798D-0F12-4AE8-B"
    "382-DE10CBD261DB"
)

remediation = (f"""
    Remediation: -

    References: {uri}

    """)


@low(
  name='rule_2313_set_the_ntp_trusted_key',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_2313_set_the_ntp_trusted_key(configuration):
    assert 'ntp trusted-key' in configuration, remediation
