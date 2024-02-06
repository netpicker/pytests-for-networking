from comfy.compliance import medium


uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-ahtml#GUID-FB9BC58A-F00A-442A-8"
    "028-1E9E260E54D3"
)

remediation = (f"""
    Remediation: hostname(config-line)# access-class <vty_acl_number> in

    References: {uri}

    """)


@medium(
  name='rule_125_set_access_class_for_line_vty',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run | sec vty <line-number> <ending-line-number>')
)
def rule_125_set_access_class_for_line_vty(commands):
    assert ' vty <line-number> <ending-line-number>' in commands.chk_cmd, remediation
