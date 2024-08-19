from comfy.compliance import low


@low(
  name='rule_241_create_a_single_interface_loopback',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip int brief | incl Loopback')
)
def rule_241_create_a_single_interface_loopback(commands, ref):
    assert 'Loopback' in commands.chk_cmd, ref
