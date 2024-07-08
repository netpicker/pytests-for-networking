from comfy.compliance import medium


@medium(
      name='rule_1_6_4_configure_logging_timestamps',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_6_4_configure_logging_timestamps(commands, ref):
    assert '' in commands.chk_cmd, ref
