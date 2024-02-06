from comfy.compliance import low

uri = (
    ""
    ""
)

remediation = (f"""
    Remediation: hostname(config)#aaa accounting commands 15 {{default | list-name | guarantee -

    References: {uri}

    """)


@low(
  name='rule_116_set_aaa_accounting_to_log_all_privileged_use_commands',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_116_set_aaa_accounting_to_log_all_privileged_use_commands(configuration):
    assert 'aaa accounting commands' in configuration, remediation
