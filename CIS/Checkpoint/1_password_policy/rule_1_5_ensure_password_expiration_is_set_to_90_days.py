from comfy.compliance import medium


@medium(
      name='rule_1_5_ensure_password_expiration_is_set_to_90_days',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_5_ensure_password_expiration_is_set_to_90_days(commands, ref):
    assert '' in commands.chk_cmd, ref
