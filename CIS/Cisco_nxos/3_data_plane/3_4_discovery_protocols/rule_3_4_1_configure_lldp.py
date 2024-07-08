from comfy.compliance import medium


@medium(
      name='rule_3_4_1_configure_lldp',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_4_1_configure_lldp(commands, ref):
    assert '' in commands.chk_cmd, ref
