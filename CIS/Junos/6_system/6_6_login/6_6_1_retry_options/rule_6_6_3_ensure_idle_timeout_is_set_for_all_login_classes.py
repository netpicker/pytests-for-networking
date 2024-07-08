from comfy.compliance import medium


@medium(
      name='rule_6_6_3_ensure_idle_timeout_is_set_for_all_login_classes',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_6_3_ensure_idle_timeout_is_set_for_all_login_classes(commands, ref):
    assert '' in commands.chk_cmd, ref
