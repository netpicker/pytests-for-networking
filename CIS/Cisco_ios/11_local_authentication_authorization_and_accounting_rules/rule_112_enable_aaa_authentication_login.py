from comfy.compliance import medium


@medium(
  name='rule_112_enable_aaa_authentication_login',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_112_enable_aaa_authentication_login(configuration, ref):
    assert 'aaa authentication login' in configuration, ref
