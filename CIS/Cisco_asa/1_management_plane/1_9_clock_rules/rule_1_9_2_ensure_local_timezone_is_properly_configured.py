from comfy.compliance import medium


@medium(
      name='rule_1_9_2_ensure_local_timezone_is_properly_configured',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_9_2_ensure_local_timezone_is_properly_configured(commands, ref):
    assert '' in commands.chk_cmd, ref
