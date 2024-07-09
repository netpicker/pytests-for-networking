from comfy.compliance import medium


@medium(
      name='rule_1_10_10_ensure_logging_trap_severity_level_is_greater_than_or_equal_to_5',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_10_10_ensure_logging_trap_severity_level_is_greater_than_or_equal_to_5(commands, ref):
    assert '' in commands.chk_cmd, ref
