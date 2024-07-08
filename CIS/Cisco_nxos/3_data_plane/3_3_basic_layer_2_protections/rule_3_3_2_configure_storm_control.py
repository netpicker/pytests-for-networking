from comfy.compliance import low


@low(
      name='rule_3_3_2_configure_storm_control',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_3_2_configure_storm_control(commands, ref):
    assert '' in commands.chk_cmd, ref
