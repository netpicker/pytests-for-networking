from comfy.compliance import medium


@medium(
      name='rule_1_3_1_pre_authentication_banner',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_3_1_pre_authentication_banner(commands, ref):
    assert '' in commands.chk_cmd, ref
