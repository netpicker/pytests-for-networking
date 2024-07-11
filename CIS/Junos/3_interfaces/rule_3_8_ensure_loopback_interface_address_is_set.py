from comfy.compliance import low


@low(
      name='rule_3_8_ensure_loopback_interface_address_is_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='show configuration interfaces lo0')
)
def rule_3_8_ensure_loopback_interface_address_is_set(commands, ref):
    assert 'address' in commands.chk_cmd, ref
