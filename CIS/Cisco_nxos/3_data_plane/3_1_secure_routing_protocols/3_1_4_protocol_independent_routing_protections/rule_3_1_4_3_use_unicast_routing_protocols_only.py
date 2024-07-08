from comfy.compliance import low


@low(
      name='rule_3_1_4_3_use_unicast_routing_protocols_only',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_1_4_3_use_unicast_routing_protocols_only(commands, ref):
    assert '' in commands.chk_cmd, ref
