from comfy.compliance import *


@medium(
    name='rule_111_enable_aaa_new_model',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_111_enable_aaa_new_model(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a2.html#GUID-E05C2E00-C01E-40"
        "53-9D12-EC37C7E8EEC5"
    )

    remediation = (f"""
Remediation: hostname(config)#aaa new-model

References: {uri}

    """)

    assert 'no aaa new-model' not in configuration, remediation
