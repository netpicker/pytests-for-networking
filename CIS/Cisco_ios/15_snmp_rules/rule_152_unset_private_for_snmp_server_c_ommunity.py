from comfy.compliance import medium


@medium(
  name='rule_152_unset_private_for_snmp_server_c_ommunity',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_152_unset_private_for_snmp_server_c_ommunity(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-s.html#GUID-2F3F13E4-EE"
        "81-4590-871D-6AE1043473DE"
    )

    remediation = (f"""
    Remediation: hostname(config)#no snmp-server community {{private}}

    References: {uri}

    """)

    assert '?' in configuration, remediation
