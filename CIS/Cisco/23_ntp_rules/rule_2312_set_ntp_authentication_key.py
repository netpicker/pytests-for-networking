from comfy.compliance import low

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/bsm/command/bsm-cr-nhtml#GUID-0435BFD1-D7D7-41D4-9"
    "7AC-7731C11226BC"
)

remediation = (f"""
    Remediation: hostname(config)#ntp authentication-key {{ntp_key_id}} md5 {{ntp_key_hash}}

    References: {uri}

    """)


@low(
  name='rule_2312_set_ntp_authentication_key',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_2312_set_ntp_authentication_key(configuration):
    assert 'ntp authentication-key' in configuration, remediation
