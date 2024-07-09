from comfy.compliance import medium


@medium(
      name='rule_2_6_2_ensure_auditlog_is_set_to_permanent',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_6_2_ensure_auditlog_is_set_to_permanent(commands, ref):
    assert '' in commands.chk_cmd, ref
