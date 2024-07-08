from comfy.compliance import medium


@medium(
      name='rule_6_1_2_ensure_accounting_of_logins',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_1_2_ensure_accounting_of_logins(commands, ref):
    assert '' in commands.chk_cmd, ref
