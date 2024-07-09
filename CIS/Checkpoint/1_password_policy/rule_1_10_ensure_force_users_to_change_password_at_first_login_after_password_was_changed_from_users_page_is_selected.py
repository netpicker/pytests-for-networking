from comfy.compliance import medium


@medium(
      name='rule_1_10_ensure_force_users_to_change_password_at_first_login_after_password_was_changed_from_users_page_is_selected',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_10_ensure_force_users_to_change_password_at_first_login_after_password_was_changed_from_users_page_is_selected(commands, ref):
    assert '' in commands.chk_cmd, ref
