from comfy.compliance import medium


@medium(
  name='rule_142_enable_service_password_encryption',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_142_enable_service_password_encryption(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/s1/sec-cr-s1.html#GUID-CC0E305A-604E-4A"
        "74-8A1A-975556CE5871"
    )

    remediation = (f"""
    Remediation: hostname(config)#service password-encryption

    References: {uri}

    """)

    assert 'service password-encryption' in configuration, remediation
