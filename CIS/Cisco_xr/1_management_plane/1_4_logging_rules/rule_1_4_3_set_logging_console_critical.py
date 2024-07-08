from comfy.compliance import medium


@medium(
      name='rule_1_4_3_set_logging_console_critical',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_4_3_set_logging_console_critical(commands, ref):
    assert '' in commands.chk_cmd, ref
