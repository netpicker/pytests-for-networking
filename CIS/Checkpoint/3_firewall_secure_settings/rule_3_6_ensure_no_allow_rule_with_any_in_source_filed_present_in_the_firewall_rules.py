from comfy.compliance import low


@low(
      name='rule_3_6_ensure_no_allow_rule_with_any_in_source_filed_present_in_the_firewall_rules',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_6_ensure_no_allow_rule_with_any_in_source_filed_present_in_the_firewall_rules(commands, ref):
    assert '' in commands.chk_cmd, ref
