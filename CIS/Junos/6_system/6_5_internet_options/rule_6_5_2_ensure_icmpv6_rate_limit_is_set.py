from comfy.compliance import low


@low(
      name='rule_6_5_2_ensure_icmpv6_rate_limit_is_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_5_2_ensure_icmpv6_rate_limit_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
