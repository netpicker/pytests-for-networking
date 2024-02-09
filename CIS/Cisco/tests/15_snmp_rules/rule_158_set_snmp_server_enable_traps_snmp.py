from comfy.compliance import medium


@medium(
  name='rule_158_set_snmp_server_enable_traps_snmp',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_158_set_snmp_server_enable_traps_snmp(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-s3.html#GUID-EB3EB677-"
        "A355-42C6-A139-85BA30810C54"
    )

    remediation = (f"""
    Remediation: hostname(config)#snmp-server enable traps snmp authentication linkup linkdown

    References: {uri}

    """)

    assert 'snmp-server' in configuration, remediation
