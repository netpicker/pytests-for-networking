from comfy.compliance import medium


@medium(
      name='rule_2_5_2_ensure_web_session_timeout_is_set_to_less_than_or_equal_to_10_minutes',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_5_2_ensure_web_session_timeout_is_set_to_less_than_or_equal_to_10_minutes(commands, ref):
    assert '' in commands.chk_cmd, ref
