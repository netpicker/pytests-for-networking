from comfy.compliance import low


@low(
  name='rule_161_configure_login_block_automated',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_161_configure_login_block_automated(configuration):
    uri = (
        "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-16-5/sec-us"
        "r-cfg-xe-16-5-book/sec-login-enhance.html"
    )

    remediation = (f"""
    Remediation: Hostname#(config)login delay {{**seconds**}}

    References: {uri}

    """)

    assert 'login block' in configuration, remediation
