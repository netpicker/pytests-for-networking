from comfy.compliance import low


@low(
  name='rule_162_autosecure',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='show auto secure config')
)
def rule_162_autosecure(commands):
    uri = (
        "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-16-5/sec-us"
        "r-cfg-xe-16-5-book/sec-autosecure.html"
    )

    remediation = (f"""
    Remediation: Hostname#(config)enable password {{password | [encryption-type ] encrypted -

    References: {uri}

    """)

    assert 'auto secure ' in commands.chk_cmd, remediation
