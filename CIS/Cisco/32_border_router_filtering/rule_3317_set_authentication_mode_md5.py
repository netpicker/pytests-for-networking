from comfy.compliance import medium


uri = (
    "3.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/command/ire-ahtml#GUID-A29E0EF6-4C"
    "EF-40A7-9824-367939001B73"
)

remediation = (f"""
    Remediation: hostname(config-router-af-interface)#authentication mode md5

    References: {uri}

    """)


@medium(
  name='rule_3317_set_authentication_mode_md5',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run | sec router eigrp')
)
def rule_3317_set_authentication_mode_md5(commands):
    assert ' router eigrp' in commands.chk_cmd, remediation
