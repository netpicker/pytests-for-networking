from comfy.compliance import medium


@medium(
      name='rule_4_2_3_ensure_authentication_check_is_not_suppressed',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_4_2_3_ensure_authentication_check_is_not_suppressed(commands, ref):
    assert '' in commands.chk_cmd, ref
