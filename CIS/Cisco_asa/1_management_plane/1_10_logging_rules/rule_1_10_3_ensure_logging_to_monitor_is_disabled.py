from comfy.compliance import medium


@medium(
      name='rule_1_10_3_ensure_logging_to_monitor_is_disabled',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_10_3_ensure_logging_to_monitor_is_disabled(commands, ref):
    assert '' in commands.chk_cmd, ref
