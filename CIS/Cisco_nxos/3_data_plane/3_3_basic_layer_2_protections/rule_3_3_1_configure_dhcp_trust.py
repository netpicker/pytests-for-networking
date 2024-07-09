from comfy.compliance import medium


@medium(
      name='rule_3_3_1_configure_dhcp_trust',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_3_1_configure_dhcp_trust(commands, ref):
    assert '' in commands.chk_cmd, ref
