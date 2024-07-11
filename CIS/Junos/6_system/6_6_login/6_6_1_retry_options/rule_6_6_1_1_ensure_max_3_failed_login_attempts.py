from comfy.compliance import medium


@medium(
      name='rule_6_6_1_1_ensure_max_3_failed_login_attempts',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_6_1_1_ensure_max_3_failed_login_attempts(commands, ref):
    assert '' in commands.chk_cmd, ref
