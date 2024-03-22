from comfy.compliance import low


@low(
  name='rule_1110_set_aaa_accounting_system',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_1110_set_aaa_accounting_system(configuration, ref):
    assert 'aaa accounting system' in configuration, ref
