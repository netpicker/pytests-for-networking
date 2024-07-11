from comfy.compliance import medium


@medium(
      name='rule_6_6_6_ensure_predefined_login_classes_are_not_used',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_6_6_ensure_predefined_login_classes_are_not_used(commands, ref):
    assert '' in commands.chk_cmd, ref
