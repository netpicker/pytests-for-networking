from comfy.compliance import medium


@medium(
      name='rule_3_1_2_1_configure_bgp_to_log_neighbor_changes',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_1_2_1_configure_bgp_to_log_neighbor_changes(commands, ref):
    assert '' in commands.chk_cmd, ref
