from comfy.compliance import low


@low(
      name='rule_4_1_2_ensure_peer_authentication_is_set_to_ipsec_sa',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_4_1_2_ensure_peer_authentication_is_set_to_ipsec_sa(commands, ref):
    assert '' in commands.chk_cmd, ref
