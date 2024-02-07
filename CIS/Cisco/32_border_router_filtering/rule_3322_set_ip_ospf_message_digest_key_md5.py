from comfy.compliance import low


@low(
  name='rule_3322_set_ip_ospf_message_digest_key_md5',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run int {<em>interface</em>}')
)
def rule_3322_set_ip_ospf_message_digest_key_md5(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_ospf/command/ospf-ihtml#GUID-939C79FF-"
        "8C09-4D5A-AEB5-DAF25038CA18"
    )

    remediation = (f"""
    Remediation: hostname(config-if)#ip ospf message-digest-key {{<em>ospf_md5_key-id</em>}} md5

    References: {uri}

    """)

    assert 'hostname#sh run int {<em>interface</em>}' in commands.chk_cmd, remediation
