from comfy.compliance import medium


@medium(
      name='rule_6_9_1_ensure_a_complex_root_password_is_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_9_1_ensure_a_complex_root_password_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
