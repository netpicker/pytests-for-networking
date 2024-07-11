from comfy.compliance import low


@low(
      name='rule_4_3_2_ensure_ospf_authentication_is_set_to_ipsec_sa_with_sha',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_4_3_2_ensure_ospf_authentication_is_set_to_ipsec_sa_with_sha(commands, ref):
    assert '' in commands.chk_cmd, ref
