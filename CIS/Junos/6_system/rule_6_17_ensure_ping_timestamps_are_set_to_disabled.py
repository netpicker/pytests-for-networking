from comfy.compliance import medium


@medium(
      name='rule_6_17_ensure_ping_timestamps_are_set_to_disabled',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_17_ensure_ping_timestamps_are_set_to_disabled(commands, ref):
    assert '' in commands.chk_cmd, ref
