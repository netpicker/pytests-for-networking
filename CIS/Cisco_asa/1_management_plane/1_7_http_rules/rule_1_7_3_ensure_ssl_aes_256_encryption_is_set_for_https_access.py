from comfy.compliance import medium


@medium(
      name='rule_1_7_3_ensure_ssl_aes_256_encryption_is_set_for_https_access',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_7_3_ensure_ssl_aes_256_encryption_is_set_for_https_access(commands, ref):
    assert '' in commands.chk_cmd, ref
