from comfy.compliance import medium


@medium(
      name='rule_2_1_7_ensure_ipv6_is_disabled_if_not_used',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_1_7_ensure_ipv6_is_disabled_if_not_used(commands, ref):
    assert '' in commands.chk_cmd, ref
