from comfy.compliance import medium


@medium(
      name='rule_1_2_6_set_the_maximum_number_of_vty_sessions',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_2_6_set_the_maximum_number_of_vty_sessions(commands, ref):
    assert '' in commands.chk_cmd, ref
