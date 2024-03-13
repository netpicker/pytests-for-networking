from comfy.compliance import low


@low(
  name='rule_242_set_aaa_source_interface',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_242_set_aaa_source_interface(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-i3.html#GUID-54A00318-CF69-"
        "46FC-9ADC-313BFC436713"
    )

    remediation = (f"""
    Remediation: Hostname(config)#ip radius source-interface loopback {loopback_interface_number}
                 or
                 Hostname(config)#aaa group server tacacs+ {{group_name}} hostname(config-sg-
                 tacacs+)#ip tacacs source-interface {loopback_interface_number}
    References: {uri}

    """)

    assert 'tacacs source | radius source' in configuration, remediation
