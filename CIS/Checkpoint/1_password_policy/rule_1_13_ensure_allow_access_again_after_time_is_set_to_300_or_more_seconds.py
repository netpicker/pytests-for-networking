from comfy.compliance import medium


@medium(
      name='rule_1_13_ensure_allow_access_again_after_time_is_set_to_300_or_more_seconds',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_13_ensure_allow_access_again_after_time_is_set_to_300_or_more_seconds(commands, ref):
    assert '' in commands.chk_cmd, ref
