from comfy.compliance import low


@low(
      name='rule_1_6_3_ensure_rsa_key_pair_is_greater_than_or_equal_to_2048_bits',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_6_3_ensure_rsa_key_pair_is_greater_than_or_equal_to_2048_bits(commands, ref):
    assert '' in commands.chk_cmd, ref
