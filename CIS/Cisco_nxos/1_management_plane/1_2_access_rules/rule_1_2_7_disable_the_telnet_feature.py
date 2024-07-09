from comfy.compliance import medium


@medium(
      name='rule_1_2_7_disable_the_telnet_feature',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_2_7_disable_the_telnet_feature(commands, ref):
    assert '' in commands.chk_cmd, ref
