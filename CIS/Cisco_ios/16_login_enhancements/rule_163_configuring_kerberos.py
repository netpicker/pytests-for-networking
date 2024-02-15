from comfy.compliance import low


@low(
  name='rule_163_configuring_kerberos',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_163_configuring_kerberos(configuration):
    uri = (
        "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-16-5/sec-us"
        "r-cfg-xe-16-5-book/sec-cfg-kerberos.html"
    )

    remediation = (f"""
    Remediation: Hostname#(config)kerberos realm {{dns-domain | host}} {{kerberos-realm}}

    References: {uri}

    """)

    assert '?' in configuration, remediation
