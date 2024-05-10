from comfy.compliance import low


@low(
  name='rule_117_set_aaa_accounting_connection',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_117_set_aaa_accounting_connection(configuration, ref):
    assert 'aaa accounting connection' in configuration, ref
