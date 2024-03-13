from comfy.compliance import medium


@medium(
  name='rule_155_set_the_acl_for_each_snmp_server_community',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_155_set_the_acl_for_each_snmp_server_community(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-s2.html#GUID-2F3F13E4-EE"
        "81-4590-871D-6AE1043473DE"
    )

    remediation = (f"""
    Remediation: hostname(config)#snmp-server community <<em>community_string</em>> ro
                 {<em>snmp_access-list_number | <span>snmp_access-list_name</span></em><span>}</span>

    References: {uri}

    """)

    assert 'snmp-server community \d+ ' in configuration, remediation
