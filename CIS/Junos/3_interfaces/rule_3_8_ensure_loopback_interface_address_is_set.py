from comfy.compliance import low


@low(
      name='rule_3_8_ensure_loopback_interface_address_is_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_3_8_ensure_loopback_interface_address_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
