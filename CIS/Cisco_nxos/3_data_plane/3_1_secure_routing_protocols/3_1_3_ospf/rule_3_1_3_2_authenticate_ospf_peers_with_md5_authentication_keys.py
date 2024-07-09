from comfy.compliance import low


@low(
      name='rule_3_1_3_2_authenticate_ospf_peers_with_md5_authentication_keys',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_1_3_2_authenticate_ospf_peers_with_md5_authentication_keys(commands, ref):
    assert '' in commands.chk_cmd, ref
