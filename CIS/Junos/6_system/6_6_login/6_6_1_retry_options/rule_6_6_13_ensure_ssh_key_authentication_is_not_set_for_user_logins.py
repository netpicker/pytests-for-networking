from comfy.compliance import medium


@medium(
      name='rule_6_6_13_ensure_ssh_key_authentication_is_not_set_for_user_logins',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_6_13_ensure_ssh_key_authentication_is_not_set_for_user_logins(commands, ref):
    assert '' in commands.chk_cmd, ref
