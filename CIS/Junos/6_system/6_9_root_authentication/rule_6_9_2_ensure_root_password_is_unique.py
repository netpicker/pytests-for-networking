from comfy.compliance import medium


@medium(
      name='rule_6_9_2_ensure_root_password_is_unique',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_9_2_ensure_root_password_is_unique(commands, ref):
    assert '' in commands.chk_cmd, ref
