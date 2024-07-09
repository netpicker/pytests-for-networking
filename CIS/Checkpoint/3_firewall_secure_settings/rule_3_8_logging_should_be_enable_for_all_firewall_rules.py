from comfy.compliance import low


@low(
      name='rule_3_8_logging_should_be_enable_for_all_firewall_rules',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_8_logging_should_be_enable_for_all_firewall_rules(commands, ref):
    assert '' in commands.chk_cmd, ref
