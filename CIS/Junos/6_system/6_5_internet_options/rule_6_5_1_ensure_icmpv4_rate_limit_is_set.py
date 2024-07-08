from comfy.compliance import low


@low(
      name='rule_6_5_1_ensure_icmpv4_rate_limit_is_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_5_1_ensure_icmpv4_rate_limit_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
