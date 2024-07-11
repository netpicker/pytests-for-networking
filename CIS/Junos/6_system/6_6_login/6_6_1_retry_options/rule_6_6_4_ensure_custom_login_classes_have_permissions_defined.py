from comfy.compliance import medium


@medium(
      name='rule_6_6_4_ensure_custom_login_classes_have_permissions_defined',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_6_4_ensure_custom_login_classes_have_permissions_defined(commands, ref):
    assert '' in commands.chk_cmd, ref
