from comfy.compliance import medium


@medium(
      name='rule_6_6_11_ensure_local_passwords_are_at_least_10_characters',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_6_11_ensure_local_passwords_are_at_least_10_characters(commands, ref):
    assert '' in commands.chk_cmd, ref
