from comfy.compliance import medium


@medium(
      name='rule_4_4_1_ensure_ospfv3_authentication_is_set_to_ipsec_sa',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_4_4_1_ensure_ospfv3_authentication_is_set_to_ipsec_sa(commands, ref):
    assert '' in commands.chk_cmd, ref
