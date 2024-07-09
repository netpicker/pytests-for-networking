from comfy.compliance import medium


@medium(
      name='rule_1_6_2_restrict_vty_access',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_6_2_restrict_vty_access(commands, ref):
    assert '' in commands.chk_cmd, ref
