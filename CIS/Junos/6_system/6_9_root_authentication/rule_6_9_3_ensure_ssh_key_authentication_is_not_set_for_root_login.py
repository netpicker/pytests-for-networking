from comfy.compliance import medium


@medium(
      name='rule_6_9_3_ensure_ssh_key_authentication_is_not_set_for_root_login',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_9_3_ensure_ssh_key_authentication_is_not_set_for_root_login(commands, ref):
    assert '' in commands.chk_cmd, ref
