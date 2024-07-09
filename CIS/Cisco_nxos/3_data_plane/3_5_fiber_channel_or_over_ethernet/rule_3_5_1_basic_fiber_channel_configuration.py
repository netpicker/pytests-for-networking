from comfy.compliance import low


@low(
      name='rule_3_5_1_basic_fiber_channel_configuration',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_5_1_basic_fiber_channel_configuration(commands, ref):
    assert '' in commands.chk_cmd, ref
