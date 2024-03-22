from comfy.compliance import low


@low(
  name='rule_118_set_aaa_accounting_exec',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_118_set_aaa_accounting_exec(configuration, ref):
    assert 'aaa accounting exec' in configuration, ref
