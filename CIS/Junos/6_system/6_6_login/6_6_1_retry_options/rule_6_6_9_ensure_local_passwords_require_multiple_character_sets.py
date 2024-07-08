from comfy.compliance import medium


@medium(
      name='rule_6_6_9_ensure_local_passwords_require_multiple_character_sets',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_6_9_ensure_local_passwords_require_multiple_character_sets(commands, ref):
    assert '' in commands.chk_cmd, ref
