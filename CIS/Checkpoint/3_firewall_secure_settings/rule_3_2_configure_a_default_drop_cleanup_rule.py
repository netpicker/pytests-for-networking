from comfy.compliance import low


@low(
      name='rule_3_2_configure_a_default_drop_cleanup_rule',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_2_configure_a_default_drop_cleanup_rule(commands, ref):
    assert '' in commands.chk_cmd, ref
