from comfy.compliance import low


@low(
      name='rule_2_1_1_1_authentication',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_2_1_1_1_authentication(commands, ref):
    assert '' in commands.chk_cmd, ref