from comfy.compliance import medium


@medium(
      name='rule_1_10_ensure_force_users_to_change_password_at_first_login',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_10_ensure_force_users_to_change_password_at_first_login(commands, ref):
    assert '' in commands.chk_cmd, ref
