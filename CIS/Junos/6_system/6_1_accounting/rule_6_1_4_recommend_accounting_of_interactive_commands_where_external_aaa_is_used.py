from comfy.compliance import low


@low(
      name='rule_6_1_4_recommend_accounting_of_interactive_commands_where_external_aaa_is_used',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_1_4_recommend_accounting_of_interactive_commands_where_external_aaa_is_used(commands, ref):
    assert '' in commands.chk_cmd, ref
