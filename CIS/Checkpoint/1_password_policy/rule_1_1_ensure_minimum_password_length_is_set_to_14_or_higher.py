from comfy.compliance import medium


@medium(
      name='rule_1_1_ensure_minimum_password_length_is_set_to_14_or_higher',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_1_ensure_minimum_password_length_is_set_to_14_or_higher(commands, ref):
    assert '' in commands.chk_cmd, ref
