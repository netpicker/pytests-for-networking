from comfy.compliance import low


@low(
      name='rule_3_1_2_2_if_possible_limit_the_bgp_routes_accepted_from_peers',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_1_2_2_if_possible_limit_the_bgp_routes_accepted_from_peers(commands, ref):
    assert '' in commands.chk_cmd, ref
