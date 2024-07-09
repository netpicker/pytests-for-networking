from comfy.compliance import medium


@medium(
      name='rule_3_1_3_3_log_ospf_adjacency_changes',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_1_3_3_log_ospf_adjacency_changes(commands, ref):
    assert '' in commands.chk_cmd, ref
