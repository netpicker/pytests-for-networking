from comfy.compliance import medium

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/security/s1/sec-cr-t2-z.html#GUID-34B3E43E-0F79-40"
    "E8-82B6-A4B5F1AFF1AD"
)

remediation = (f"""
    Remediation: hostname(config)#username <LOCAL_USERNAME> privilege 1

    References: {uri}

    """)


@medium(
  name='rule_121_set_privilege_1_for_local_users',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_121_set_privilege_1_for_local_users(configuration):
    assert 'privilege' in configuration, remediation
