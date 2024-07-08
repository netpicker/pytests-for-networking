from comfy.compliance import medium


@medium(
      name='rule_6_23_ensure_password_is_set_for_pic_console_authentication',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_23_ensure_password_is_set_for_pic_console_authentication(commands, ref):
    assert '' in commands.chk_cmd, ref
