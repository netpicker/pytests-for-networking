from comfy.compliance import medium


@medium(
  name='rule_223_set_logging_console_critical',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_223_set_logging_console_critical(configuration):
    remediation = (f"""
    Remediation: hostname(config)#logging console critical

    """)

    assert 'logging console' in configuration, remediation
