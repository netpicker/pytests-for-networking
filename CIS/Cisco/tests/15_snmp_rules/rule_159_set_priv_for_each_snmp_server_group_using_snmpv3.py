from comfy.compliance import low


@low(
  name='rule_159_set_priv_for_each_snmp_server_group_using_snmpv3',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='show snmp group')
)
def rule_159_set_priv_for_each_snmp_server_group_using_snmpv3(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-s5.html#GUID-56E87D02-"
        "C56F-4E2D-A5C8-617E31740C3F"
    )

    remediation = (f"""
    Remediation: hostname(config)#snmp-server group {{<em>group_name</em>}} v3 priv

    References: {uri}

    """)

    assert 'hostname#show snmp group' in commands.chk_cmd, remediation
