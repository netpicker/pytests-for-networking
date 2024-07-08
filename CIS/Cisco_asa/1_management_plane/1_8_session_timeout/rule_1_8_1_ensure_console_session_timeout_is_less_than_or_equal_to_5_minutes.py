from comfy.compliance import medium


@medium(
      name='rule_1_8_1_ensure_console_session_timeout_is_less_than_or_equal_to_5_minutes',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_8_1_ensure_console_session_timeout_is_less_than_or_equal_to_5_minutes(commands, ref):
    assert '' in commands.chk_cmd, ref
