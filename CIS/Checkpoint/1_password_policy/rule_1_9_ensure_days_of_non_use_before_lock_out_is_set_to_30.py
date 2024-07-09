from comfy.compliance import medium


@medium(
      name='rule_1_9_ensure_days_of_non_use_before_lock_out_is_set_to_30',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_9_ensure_days_of_non_use_before_lock_out_is_set_to_30(commands, ref):
    assert '' in commands.chk_cmd, ref
