from comfy.compliance import medium


@medium(
      name='rule_2_1_1_configure_control_plane_policing',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_2_1_1_configure_control_plane_policing(commands, ref):
    assert '' in commands.chk_cmd, ref
