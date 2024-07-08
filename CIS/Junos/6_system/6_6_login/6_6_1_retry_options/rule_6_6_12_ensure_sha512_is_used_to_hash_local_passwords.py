from comfy.compliance import medium


@medium(
      name='rule_6_6_12_ensure_sha512_is_used_to_hash_local_passwords',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_6_12_ensure_sha512_is_used_to_hash_local_passwords(commands, ref):
    assert '' in commands.chk_cmd, ref
