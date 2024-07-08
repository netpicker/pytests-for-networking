from comfy.compliance import medium


@medium(
      name='rule_5_3_ensure_a_client_list_is_set_for_snmpv1_v2_communities',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_5_3_ensure_a_client_list_is_set_for_snmpv1_v2_communities(commands, ref):
    assert '' in commands.chk_cmd, ref
