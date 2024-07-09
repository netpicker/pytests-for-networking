from comfy.compliance import medium


@medium(
      name='rule_1_4_ensure_check_for_password_reuse_is_selected_and_history_length_is_set_to_12_or_more',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_4_ensure_check_for_password_reuse_is_selected_and_history_length_is_set_to_12_or_more(commands, ref):
    assert '' in commands.chk_cmd, ref
