from comfy.compliance import medium


@medium(
      name='rule_4_1_5_ensure_ingress_filtering_is_set_for_ebgp_peers',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_4_1_5_ensure_ingress_filtering_is_set_for_ebgp_peers(commands, ref):
    assert '' in commands.chk_cmd, ref
