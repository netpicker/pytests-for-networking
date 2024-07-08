from comfy.compliance import medium


@medium(
      name='rule_6_10_5_8_ensure_rest_allowed_sources_is_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_5_8_ensure_rest_allowed_sources_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
