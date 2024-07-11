from comfy.compliance import medium


@medium(
      name='rule_6_6_1_2_ensure_max_login_backoff_threshold_of_2',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_6_1_2_ensure_max_login_backoff_threshold_of_2(commands, ref):
    assert '' in commands.chk_cmd, ref
