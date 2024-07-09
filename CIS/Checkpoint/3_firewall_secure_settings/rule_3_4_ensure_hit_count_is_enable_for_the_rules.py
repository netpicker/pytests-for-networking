from comfy.compliance import low


@low(
      name='rule_3_4_ensure_hit_count_is_enable_for_the_rules',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_4_ensure_hit_count_is_enable_for_the_rules(commands, ref):
    assert '' in commands.chk_cmd, ref
