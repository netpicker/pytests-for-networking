from comfy.compliance import medium


@medium(
  name='rule_221_set_logging_enable',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_221_set_logging_enable(configuration):
    uri = (
        "https://community.cisco.com/t5/networking-knowledge-base/how-to-configure-logging-in-cisco"
        "-ios/ta-p/3132434"
    )

    remediation = (f"""
    Remediation: hostname(config)#archive
                 hostname(config-archive)#log config
                 hostname(config-archive-log-cfg)#logging enable
                 hostname(config-archive-log-cfg)#end

    References: {uri}

    """)

    assert 'logging enable' in configuration, remediation
