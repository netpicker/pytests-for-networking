from comfy.compliance import low


# We have to define the actual interface here
@low(
  name='rule_322_set_inbound_ip_access_group_on_the_external_interface',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh run | sec interface {external_interface}')
)
def rule_322_set_inbound_ip_access_group_on_the_external_interface(commands, ref):
    assert 'ip access-group ' in commands.chk_cmd, ref
    assert ' in' in commands.chk_cmd, ref
