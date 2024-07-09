from comfy.compliance import low


@low(
      name='rule_3_5_2_configure_fcoe_zoning',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_5_2_configure_fcoe_zoning(commands, ref):
    assert '' in commands.chk_cmd, ref
