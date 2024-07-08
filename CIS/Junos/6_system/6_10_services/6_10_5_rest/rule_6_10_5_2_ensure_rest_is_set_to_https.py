from comfy.compliance import medium


@medium(
      name='rule_6_10_5_2_ensure_rest_is_set_to_https',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_5_2_ensure_rest_is_set_to_https(commands, ref):
    assert '' in commands.chk_cmd, ref
