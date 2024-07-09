from comfy.compliance import medium


@medium(
      name='rule_1_1_3_ensure_master_key_passphrase_is_set',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_1_3_ensure_master_key_passphrase_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
