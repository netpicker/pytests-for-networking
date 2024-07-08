from comfy.compliance import low


@low(
      name='rule_6_2_1_ensure_archive_on_commit',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_2_1_ensure_archive_on_commit(commands, ref):
    assert '' in commands.chk_cmd, ref
