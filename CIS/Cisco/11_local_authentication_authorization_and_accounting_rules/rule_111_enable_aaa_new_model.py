from comfy.compliance import medium


@medium(
  name='rule_111_enable_aaa_new_model',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_111_enable_aaa_new_model(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-ahtml#GUID-E05C2E00-C01E-40"
        "53-9D12-EC37C7E8EEC5"
    )

    remediation = (f"""
    Remediation: hostname(config)#aaa new-model

    References: {uri}

    """)

    assert 'aaa new-model' in configuration, remediation
