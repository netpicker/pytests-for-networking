from comfy.compliance import medium


@medium(
  name='rule_151_set_no_snmp_server_to_disable_snmp_when_unused',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='show snmp community')
)
def rule_151_set_no_snmp_server_to_disable_snmp_when_unused(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-book.html"
        ""
    )

    remediation = (f"""
    Remediation: hostname(config)#no snmp-server

    References: {uri}

    """)

    assert 'hostname#show snmp community' in commands.chk_cmd, remediation
