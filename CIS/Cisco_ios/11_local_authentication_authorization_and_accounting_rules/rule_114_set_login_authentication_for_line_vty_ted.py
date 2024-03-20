from comfy.compliance import medium

@medium(
  name='rule_114_set_login_authentication_for_line_vty_ted',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='show running-config | sec line | incl login authentication')
)
def rule_114_set_login_authentication_for_line_vty_ted(commands,ref):
    assert ' login authentication' in commands.chk_cmd, ref
