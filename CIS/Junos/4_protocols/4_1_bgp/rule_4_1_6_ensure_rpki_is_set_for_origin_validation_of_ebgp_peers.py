from comfy.compliance import low


@low(
      name='rule_4_1_6_ensure_rpki_is_set_for_origin_validation_of_ebgp_peers',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_4_1_6_ensure_rpki_is_set_for_origin_validation_of_ebgp_peers(commands, ref):
    assert '' in commands.chk_cmd, ref
