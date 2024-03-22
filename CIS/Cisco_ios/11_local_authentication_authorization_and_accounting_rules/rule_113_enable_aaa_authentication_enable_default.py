from comfy.compliance import medium


@medium(
  name='rule_113_enable_aaa_authentication_enable_default',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_113_enable_aaa_authentication_enable_default(configuration, ref):
    assert 'aaa authentication enable' in configuration, ref
