from comfy.compliance import low


@low(
      name='rule_3_1_4_2_create_and_use_a_single_loopback_address_for_routing_protocol_peering',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_1_4_2_create_and_use_a_single_loopback_address_for_routing_protocol_peering(commands, ref):
    assert '' in commands.chk_cmd, ref
