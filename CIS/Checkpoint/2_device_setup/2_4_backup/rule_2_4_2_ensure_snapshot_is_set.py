from comfy.compliance import medium


@medium(
      name='rule_2_4_2_ensure_snapshot_is_set',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_4_2_ensure_snapshot_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
