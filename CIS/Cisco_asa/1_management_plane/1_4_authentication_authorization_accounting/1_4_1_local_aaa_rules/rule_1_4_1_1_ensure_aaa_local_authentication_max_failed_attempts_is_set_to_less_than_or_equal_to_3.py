from comfy.compliance import medium


@medium(
      name='rule_1_4_1_1_ensure_aaa_local_authentication_max_failed_attempts_is_set_to_less_than_or_equal_to_3',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_4_1_1_ensure_aaa_local_authentication_max_failed_attempts_is_set_to_less_than_or_equal_to_3(commands, ref):
    assert '' in commands.chk_cmd, ref
