from comfy.compliance import medium


@medium(
      name='rule_2_3_2_ensure_timezone_is_properly_configured',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_3_2_ensure_timezone_is_properly_configured(commands, ref):
    assert '' in commands.chk_cmd, ref
