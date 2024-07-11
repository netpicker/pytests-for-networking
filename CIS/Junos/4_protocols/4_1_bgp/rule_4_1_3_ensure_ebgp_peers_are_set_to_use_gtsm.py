from comfy.compliance import medium


@medium(
      name='rule_4_1_3_ensure_ebgp_peers_are_set_to_use_gtsm',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_4_1_3_ensure_ebgp_peers_are_set_to_use_gtsm(commands, ref):
    assert '' in commands.chk_cmd, ref
