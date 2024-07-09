from comfy.compliance import medium


@medium(
      name='rule_1_4_4_set_password_length_for_local_credentials',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_4_4_set_password_length_for_local_credentials(commands, ref):
    assert '' in commands.chk_cmd, ref
