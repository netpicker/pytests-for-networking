from comfy.compliance import medium


@medium(
      name='rule_1_7_ensure_lockout_users_after_password_expiration_is_set_to_1',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_7_ensure_lockout_users_after_password_expiration_is_set_to_1(commands, ref):
    assert '' in commands.chk_cmd, ref
