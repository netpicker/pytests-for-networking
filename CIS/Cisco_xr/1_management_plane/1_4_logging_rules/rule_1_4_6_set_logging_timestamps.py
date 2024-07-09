from comfy.compliance import medium


@medium(
      name='rule_1_4_6_set_logging_timestamps',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_4_6_set_logging_timestamps(commands, ref):
    assert '' in commands.chk_cmd, ref
