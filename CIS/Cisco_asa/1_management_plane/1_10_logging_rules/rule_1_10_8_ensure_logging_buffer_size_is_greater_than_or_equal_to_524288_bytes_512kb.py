from comfy.compliance import medium


@medium(
      name='rule_1_10_8_ensure_logging_buffer_size_is_greater_than_or_equal_to_524288_bytes_512kb',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_10_8_ensure_logging_buffer_size_is_greater_than_or_equal_to_524288_bytes_512kb(commands, ref):
    assert '' in commands.chk_cmd, ref
