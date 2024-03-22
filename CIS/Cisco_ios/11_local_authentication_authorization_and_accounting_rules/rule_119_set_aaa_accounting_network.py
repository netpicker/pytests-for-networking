from comfy.compliance import low


@low(
  name='rule_119_set_aaa_accounting_network',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_119_set_aaa_accounting_network(configuration, ref):
    assert 'aaa accounting network' in configuration, ref
