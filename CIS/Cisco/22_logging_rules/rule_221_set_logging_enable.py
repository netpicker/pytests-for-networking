from comfy.compliance import medium

uri = (
    "https://community.cisco.com/t5/networking-knowledge-base/how-to-configure-logging-in-cisco-ios"
    "/ta-p/3132434"
)

remediation = (f"""
    Remediation: hostname(config-archive-log-cfg)#end

    References: {uri}

    """)


@medium(
  name='rule_221_set_logging_enable',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_221_set_logging_enable(configuration):
    assert 'logging host' in configuration, remediation
