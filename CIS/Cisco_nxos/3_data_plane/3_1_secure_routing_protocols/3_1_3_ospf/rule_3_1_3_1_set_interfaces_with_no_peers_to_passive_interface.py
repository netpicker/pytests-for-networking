from comfy.compliance import medium


@medium(
      name='rule_3_1_3_1_set_interfaces_with_no_peers_to_passive_interface',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_1_3_1_set_interfaces_with_no_peers_to_passive_interface(commands, ref):
    assert '' in commands.chk_cmd, ref
