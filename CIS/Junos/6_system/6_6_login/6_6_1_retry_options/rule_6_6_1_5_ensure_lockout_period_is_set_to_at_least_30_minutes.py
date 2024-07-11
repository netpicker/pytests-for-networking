from comfy.compliance import medium


@medium(
      name='rule_6_6_1_5_ensure_lockout_period_is_set_to_at_least_30_minutes',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_6_1_5_ensure_lockout_period_is_set_to_at_least_30_minutes(commands, ref):
    assert '' in commands.chk_cmd, ref
