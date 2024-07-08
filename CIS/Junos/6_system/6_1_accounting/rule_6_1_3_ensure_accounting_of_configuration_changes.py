from comfy.compliance import medium


@medium(
      name='rule_6_1_3_ensure_accounting_of_configuration_changes',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_1_3_ensure_accounting_of_configuration_changes(commands, ref):
    assert '' in commands.chk_cmd, ref
