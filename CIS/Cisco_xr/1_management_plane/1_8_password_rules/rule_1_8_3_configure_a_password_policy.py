from comfy.compliance import low


@low(
      name='rule_1_8_3_configure_a_password_policy',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_8_3_configure_a_password_policy(commands, ref):
    assert '' in commands.chk_cmd, ref
