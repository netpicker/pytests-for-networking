from comfy.compliance import medium


@medium(
      name='rule_1_1_1_3_configure_aaa_authentication___radius_if_applicable',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_1_1_3_configure_aaa_authentication___radius_if_applicable(commands, ref):
    assert '' in commands.chk_cmd, ref
