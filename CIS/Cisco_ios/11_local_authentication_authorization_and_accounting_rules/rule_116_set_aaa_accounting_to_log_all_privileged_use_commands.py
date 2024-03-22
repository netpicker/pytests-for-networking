from comfy.compliance import low


@low(
  name='rule_116_set_aaa_accounting_to_log_all_privileged_use_commands',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_116_set_aaa_accounting_to_log_all_privileged_use_commands(configuration, ref):
    assert 'aaa accounting commands' in configuration, ref
