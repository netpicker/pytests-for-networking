from comfy.compliance import medium


@medium(
      name='rule_3_2_1_1_configure_ra_guard',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_2_1_1_configure_ra_guard(commands, ref):
    assert '' in commands.chk_cmd, ref
