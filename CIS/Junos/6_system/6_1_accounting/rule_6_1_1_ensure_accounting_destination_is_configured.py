from comfy.compliance import medium


@medium(
      name='rule_6_1_1_ensure_accounting_destination_is_configured',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_1_1_ensure_accounting_destination_is_configured(commands, ref):
    assert '' in commands.chk_cmd, ref
