from comfy.compliance import low


@low(
      name='rule_1_8_1_enable_aes_password_encryption',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_8_1_enable_aes_password_encryption(commands, ref):
    assert '' in commands.chk_cmd, ref
