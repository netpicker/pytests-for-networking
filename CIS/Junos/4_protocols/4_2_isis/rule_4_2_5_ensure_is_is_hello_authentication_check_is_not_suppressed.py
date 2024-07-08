from comfy.compliance import medium


@medium(
      name='rule_4_2_5_ensure_is_is_hello_authentication_check_is_not_suppressed',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_4_2_5_ensure_is_is_hello_authentication_check_is_not_suppressed(commands, ref):
    assert '' in commands.chk_cmd, ref
