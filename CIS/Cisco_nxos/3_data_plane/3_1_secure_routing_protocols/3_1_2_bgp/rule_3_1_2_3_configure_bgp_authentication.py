from comfy.compliance import low


@low(
      name='rule_3_1_2_3_configure_bgp_authentication',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_1_2_3_configure_bgp_authentication(commands, ref):
    assert '' in commands.chk_cmd, ref
