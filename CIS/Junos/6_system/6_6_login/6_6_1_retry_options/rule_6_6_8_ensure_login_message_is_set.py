from comfy.compliance import medium


@medium(
      name='rule_6_6_8_ensure_login_message_is_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_6_8_ensure_login_message_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
