from comfy.compliance import medium


@medium(
      name='rule_1_4_5_set_logging_trap_informational',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_4_5_set_logging_trap_informational(commands, ref):
    assert '' in commands.chk_cmd, ref
