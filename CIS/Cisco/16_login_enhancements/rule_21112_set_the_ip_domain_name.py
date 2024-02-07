from comfy.compliance import medium


@medium(
  name='rule_21112_set_the_ip_domain_name',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_21112_set_the_ip_domain_name(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/ipaddr/command/ipaddr-i3.html#GUID-A706D62B-91"
        "70-45CE-A2C2-7B2052BE2CAB"
    )

    remediation = (f"""
    Remediation: hostname (config)#ip domain-name {{<em>domain-name</em>}}

    References: {uri}

    """)

    assert 'domain-name' in configuration, remediation
