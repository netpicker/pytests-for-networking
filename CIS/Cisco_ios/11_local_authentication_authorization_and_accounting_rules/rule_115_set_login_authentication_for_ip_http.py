from comfy.compliance import medium


@medium(
  name='rule_115_set_login_authentication_for_ip_http_ed',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_115_set_login_authentication_for_ip_http_ed(configuration,ref):
    assert 'ip http authentication' in configuration, ref
