from comfy.compliance import medium


@medium(
  name='rule_111_enable_aaa_new_model',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_111_enable_aaa_new_model(configuration, ref):
    assert 'no aaa new-model' not in configuration, ref
