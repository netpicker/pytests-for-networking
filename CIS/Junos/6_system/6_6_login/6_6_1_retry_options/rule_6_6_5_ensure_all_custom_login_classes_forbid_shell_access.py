from comfy.compliance import medium


@medium(
      name='rule_6_6_5_ensure_all_custom_login_classes_forbid_shell_access',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_6_5_ensure_all_custom_login_classes_forbid_shell_access(commands, ref):
    assert '' in commands.chk_cmd, ref
