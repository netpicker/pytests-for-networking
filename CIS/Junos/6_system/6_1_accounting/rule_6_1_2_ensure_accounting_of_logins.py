from comfy.compliance import medium


@medium(
      name='rule_6_1_2_ensure_accounting_of_logins',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='show configuration system accounting')
)
def rule_6_1_2_ensure_accounting_of_logins(commands, ref):
    assert 'events login;' in commands.chk_cmd, ref
