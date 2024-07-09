from comfy.compliance import medium


@medium(
      name='rule_1_7_2_configure_a_time_zone',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_7_2_configure_a_time_zone(commands, ref):
    assert '' in commands.chk_cmd, ref
