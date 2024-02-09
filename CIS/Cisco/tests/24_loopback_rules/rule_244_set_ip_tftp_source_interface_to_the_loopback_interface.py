from comfy.compliance import low


@low(
  name='rule_244_set_ip_tftp_source_interface_to_the_loopback_interface',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_244_set_ip_tftp_source_interface_to_the_loopback_interface(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/F_through_K.html#GUID-9AA"
        "27050-A578-47CD-9F1D-5A8E2B449209"
    )

    remediation = (f"""
    Remediation: hostname(config)#ip tftp source-interface loopback

    References: {uri}

    """)

    assert 'tftp source-interface' in configuration, remediation