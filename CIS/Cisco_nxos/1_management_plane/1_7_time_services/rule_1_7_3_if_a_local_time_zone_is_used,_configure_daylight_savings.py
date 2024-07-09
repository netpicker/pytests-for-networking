from comfy.compliance import medium


@medium(
      name='rule_1_7_3_if_a_local_time_zone_is_used,_configure_daylight_savings',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_7_3_if_a_local_time_zone_is_used,_configure_daylight_savings(commands, ref):
    assert '' in commands.chk_cmd, ref
