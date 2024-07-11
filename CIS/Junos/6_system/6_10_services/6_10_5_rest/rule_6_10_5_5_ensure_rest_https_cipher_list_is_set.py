from comfy.compliance import medium


@medium(
      name='rule_6_10_5_5_ensure_rest_https_cipher_list_is_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_5_5_ensure_rest_https_cipher_list_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
