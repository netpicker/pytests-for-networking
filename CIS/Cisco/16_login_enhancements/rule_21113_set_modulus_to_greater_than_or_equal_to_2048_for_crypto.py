from comfy.compliance import medium


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-c4.html#GUID-2AECF701-D54A-404E"
    "-9614-D3AAB049BC13"
)

remediation = (f"""
    Remediation: hostname(config)#crypto key generate rsa general-keys modulus <em>2048</em>

    References: {uri}

    """)


@medium(
  name='rule_21113_set_modulus_to_greater_than_or_equal_to_2048_for_crypto',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh crypto key mypubkey rsa')
)
def rule_21113_set_modulus_to_greater_than_or_equal_to_2048_for_crypto(commands):
    assert 'hostname#sh crypto key mypubkey rsa' in commands.chk_cmd, remediation
