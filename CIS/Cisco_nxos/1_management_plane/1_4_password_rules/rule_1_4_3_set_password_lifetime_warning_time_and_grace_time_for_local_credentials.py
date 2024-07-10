from comfy.compliance import medium


@medium(
      name='rule_1_4_3_set_password_lifetime_warning_time_and_grace_time_for_local_credentials',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_4_3_set_password_lifetime_warning_time_and_grace_time_for_local_credentials(commands, ref):
    assert '' in commands.chk_cmd, ref
