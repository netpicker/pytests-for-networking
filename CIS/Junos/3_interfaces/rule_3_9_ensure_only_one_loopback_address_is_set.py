from comfy.compliance import medium


@medium(
      name='rule_3_9_ensure_only_one_loopback_address_is_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_3_9_ensure_only_one_loopback_address_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
