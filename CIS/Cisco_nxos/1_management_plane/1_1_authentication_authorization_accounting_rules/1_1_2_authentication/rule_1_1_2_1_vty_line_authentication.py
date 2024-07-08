from comfy.compliance import medium


@medium(
      name='rule_1_1_2_1_vty_line_authentication',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_1_2_1_vty_line_authentication(commands, ref):
    assert '' in commands.chk_cmd, ref
