from comfy.compliance import low


@low(
      name='rule_3_1_enable_the_firewall_stealth_rule',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_1_enable_the_firewall_stealth_rule(commands, ref):
    assert '' in commands.chk_cmd, ref
