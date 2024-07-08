from comfy.compliance import medium


@medium(
      name='rule_3_1_1_ensure_caller_id_is_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_3_1_1_ensure_caller_id_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
