from comfy.compliance import low


@low(
      name='rule_3_10_ensure_activex_filtering_is_enabled',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_3_10_ensure_activex_filtering_is_enabled(commands, ref):
    assert '' in commands.chk_cmd, ref
