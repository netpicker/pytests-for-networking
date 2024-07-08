from comfy.compliance import medium


@medium(
      name='rule_1_6_ensure_warn_users_before_password_expiration_is_set_to_7_days',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_6_ensure_warn_users_before_password_expiration_is_set_to_7_days(commands, ref):
    assert '' in commands.chk_cmd, ref
