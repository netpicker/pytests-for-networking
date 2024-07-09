from comfy.compliance import medium


@medium(
      name='rule_1_12_ensure_maximum_number_of_failed_attempts_allowed_is_set_to_5_or_fewer',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_12_ensure_maximum_number_of_failed_attempts_allowed_is_set_to_5_or_fewer(commands, ref):
    assert '' in commands.chk_cmd, ref
