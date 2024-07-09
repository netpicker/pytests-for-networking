from comfy.compliance import medium


@medium(
      name='rule_1_3_ensure_password_complexity_is_set_to_3',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_3_ensure_password_complexity_is_set_to_3(commands, ref):
    assert '' in commands.chk_cmd, ref
