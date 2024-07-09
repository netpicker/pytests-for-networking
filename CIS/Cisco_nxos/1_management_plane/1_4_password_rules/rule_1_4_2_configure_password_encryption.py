from comfy.compliance import low


@low(
      name='rule_1_4_2_configure_password_encryption',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_4_2_configure_password_encryption(commands, ref):
    assert '' in commands.chk_cmd, ref
