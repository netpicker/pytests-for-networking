from comfy.compliance import medium


@medium(
      name='rule_2_4_1_ensure_system_backup_is_set',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_4_1_ensure_system_backup_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
