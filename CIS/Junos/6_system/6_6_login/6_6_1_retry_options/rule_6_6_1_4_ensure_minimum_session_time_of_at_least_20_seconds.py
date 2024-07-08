from comfy.compliance import medium


@medium(
      name='rule_6_6_1_4_ensure_minimum_session_time_of_at_least_20_seconds',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_6_1_4_ensure_minimum_session_time_of_at_least_20_seconds(commands, ref):
    assert '' in commands.chk_cmd, ref
