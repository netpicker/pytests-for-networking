from comfy.compliance import medium


@medium(
      name='rule_3_1_4_4_configure_hsrp_protections',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_1_4_4_configure_hsrp_protections(commands, ref):
    assert '' in commands.chk_cmd, ref
