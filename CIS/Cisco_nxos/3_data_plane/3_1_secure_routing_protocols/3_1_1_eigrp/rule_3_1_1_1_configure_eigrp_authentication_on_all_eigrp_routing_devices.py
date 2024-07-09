from comfy.compliance import low


@low(
      name='rule_3_1_1_1_configure_eigrp_authentication_on_all_eigrp_routing_devices',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_1_1_1_configure_eigrp_authentication_on_all_eigrp_routing_devices(commands, ref):
    assert '' in commands.chk_cmd, ref
