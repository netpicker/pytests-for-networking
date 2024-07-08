from comfy.compliance import low


@low(
      name='rule_6_10_5_6_ensure_rest_https_cipher_list_is_set_to_suite_b_only',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_5_6_ensure_rest_https_cipher_list_is_set_to_suite_b_only(commands, ref):
    assert '' in commands.chk_cmd, ref
