from comfy.compliance import low


@low(
      name='rule_1_1_1_2_radius',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_1_1_2_radius(commands, ref):
    assert '' in commands.chk_cmd, ref
