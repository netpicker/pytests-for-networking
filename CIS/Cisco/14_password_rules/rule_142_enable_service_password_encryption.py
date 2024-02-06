from comfy.compliance import medium

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/security/s1/sec-cr-shtml#GUID-CC0E305A-604E-4A74-8"
    "A1A-975556CE5871"
)

remediation = (f"""
    Remediation: hostname(config)#service password-encryption

    References: {uri}

    """)


@medium(
  name='rule_142_enable_service_password_encryption',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_142_enable_service_password_encryption(configuration):
    assert 'service password-encryption' in configuration, remediation
