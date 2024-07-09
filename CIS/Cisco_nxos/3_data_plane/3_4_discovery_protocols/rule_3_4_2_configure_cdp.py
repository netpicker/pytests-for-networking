from comfy.compliance import low


@low(
      name='rule_3_4_2_configure_cdp',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_4_2_configure_cdp(commands, ref):
    assert '' in commands.chk_cmd, ref
