from comfy.compliance import medium


@medium(
      name='rule_1_2_3_limit_ssh_login_attempts',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_2_3_limit_ssh_login_attempts(commands, ref):
    assert '' in commands.chk_cmd, ref
