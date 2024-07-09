from comfy.compliance import medium


@medium(
      name='rule_2_6_1_ensure_mgmtauditlogs_is_set_to_on',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_6_1_ensure_mgmtauditlogs_is_set_to_on(commands, ref):
    assert '' in commands.chk_cmd, ref
