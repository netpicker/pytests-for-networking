from comfy.compliance import medium

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-shtml#GUID-2F3F13E4-EE81-4"
    "590-871D-6AE1043473DE"
)

remediation = (f"""
    Remediation: hostname(config)#no snmp-server community {{private}}

    References: {uri}

    """)


@medium(
  name='rule_152_unset_private_for_snmp_server_c_ommunity',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_152_unset_private_for_snmp_server_c_ommunity(configuration):
    assert '' in configuration, remediation
