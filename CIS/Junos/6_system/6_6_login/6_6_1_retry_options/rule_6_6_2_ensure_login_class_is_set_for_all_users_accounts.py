from comfy.compliance import medium


@medium(
      name='rule_6_6_2_ensure_login_class_is_set_for_all_users_accounts',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_6_2_ensure_login_class_is_set_for_all_users_accounts(commands, ref):
    assert '' in commands.chk_cmd, ref
