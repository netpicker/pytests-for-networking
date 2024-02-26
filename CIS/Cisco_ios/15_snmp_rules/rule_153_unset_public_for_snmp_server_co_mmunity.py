from comfy.compliance import medium


@medium(
  name='rule_153_unset_public_for_snmp_server_co_mmunity',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_153_unset_public_for_snmp_server_co_mmunity(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-s.html#GUID-2F3F13E4-EE"
        "81-4590-871D-6AE1043473DE"
    )

    remediation = (f"""
    Remediation: hostname(config)#no snmp-server communi ty {{public}}

    References: {uri}

    """)

    assert '?' in configuration, remediation
