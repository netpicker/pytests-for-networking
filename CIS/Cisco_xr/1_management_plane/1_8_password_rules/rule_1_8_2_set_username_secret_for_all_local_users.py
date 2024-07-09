from comfy.compliance import medium


@medium(
      name='rule_1_8_2_set_username_secret_for_all_local_users',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_8_2_set_username_secret_for_all_local_users(commands, ref):
    assert '' in commands.chk_cmd, ref
