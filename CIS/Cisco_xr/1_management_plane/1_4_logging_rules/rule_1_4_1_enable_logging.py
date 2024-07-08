from comfy.compliance import medium


@medium(
      name='rule_1_4_1_enable_logging',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_4_1_enable_logging(commands, ref):
    assert '' in commands.chk_cmd, ref
