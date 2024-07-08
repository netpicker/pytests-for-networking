from comfy.compliance import low


@low(
      name='rule_1_9_management_plane_protection',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_9_management_plane_protection(commands, ref):
    assert '' in commands.chk_cmd, ref
