from comfy.compliance import low


uri = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-16-5/sec-usr-cf"
    "g-xe-16-5-book/sec-autosecure.html"
)

remediation = (f"""
    Remediation: Hostname#(config)enable password {{password | [encryption-type ] encrypted -

    References: {uri}

    """)


@low(
  name='rule_162_autosecure',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='Hostname#show auto secure config')
)
def rule_162_autosecure(commands):
    assert 'ure config' in commands.chk_cmd, remediation
