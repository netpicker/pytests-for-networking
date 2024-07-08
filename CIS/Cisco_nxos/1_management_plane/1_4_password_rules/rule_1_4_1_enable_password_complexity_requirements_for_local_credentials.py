from comfy.compliance import medium


@medium(
      name='rule_1_4_1_enable_password_complexity_requirements_for_local_credentials',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_4_1_enable_password_complexity_requirements_for_local_credentials(commands, ref):
    assert '' in commands.chk_cmd, ref
