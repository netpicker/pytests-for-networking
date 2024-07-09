from comfy.compliance import low


@low(
      name='rule_3_9_review_and_log_implied_rules',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_9_review_and_log_implied_rules(commands, ref):
    assert '' in commands.chk_cmd, ref
