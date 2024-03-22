from comfy.compliance import low


@low(
  name='rule_242_set_aaa_source_interface',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_242_set_aaa_source_interface(configuration, ref):
    assert 'tacacs source | radius source' in configuration, ref
