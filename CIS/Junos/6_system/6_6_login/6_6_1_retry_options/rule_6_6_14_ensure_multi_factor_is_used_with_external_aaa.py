from comfy.compliance import low


@low(
      name='rule_6_6_14_ensure_multi_factor_is_used_with_external_aaa',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_6_14_ensure_multi_factor_is_used_with_external_aaa(commands, ref):
    assert '' in commands.chk_cmd, ref
