from comfy.compliance import low

uri = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/config-mgmt/configuration/xe-16-6/config-mgm"
    "t-xe-16-6-book/cm-config-logger.pdf"
)

remediation = (f"""
    Remediation: hostname(config)#end

    References: {uri}

    """)


@low(
  name='rule_228_set_login_successfailure_logging_d',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_228_set_login_successfailure_logging_d(configuration):
    assert '' in configuration, remediation
