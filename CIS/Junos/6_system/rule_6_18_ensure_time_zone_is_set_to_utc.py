from comfy.compliance import low


@low(
      name='rule_6_18_ensure_time_zone_is_set_to_utc',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_18_ensure_time_zone_is_set_to_utc(commands, ref):
    assert '' in commands.chk_cmd, ref
