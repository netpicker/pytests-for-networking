from comfy.compliance import low


@low(
      name='rule_6_15_ensure_multicast_echo_is_set_to_disabled',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_15_ensure_multicast_echo_is_set_to_disabled(commands, ref):
    assert '' in commands.chk_cmd, ref
