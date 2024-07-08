from comfy.compliance import medium


@medium(
      name='rule_1_2_1_restrict_access_to_vty_sessions',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_2_1_restrict_access_to_vty_sessions(commands, ref):
    assert '' in commands.chk_cmd, ref
