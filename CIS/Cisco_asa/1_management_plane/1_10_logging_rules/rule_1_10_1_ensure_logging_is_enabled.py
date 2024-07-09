from comfy.compliance import medium


@medium(
      name='rule_1_10_1_ensure_logging_is_enabled',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_10_1_ensure_logging_is_enabled(commands, ref):
    assert '' in commands.chk_cmd, ref
