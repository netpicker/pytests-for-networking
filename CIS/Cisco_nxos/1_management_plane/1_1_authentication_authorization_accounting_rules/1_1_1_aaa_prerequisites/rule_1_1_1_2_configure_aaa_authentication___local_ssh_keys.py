from comfy.compliance import medium


@medium(
      name='rule_1_1_1_2_configure_aaa_authentication___local_ssh_keys',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_1_1_2_configure_aaa_authentication___local_ssh_keys(commands, ref):
    assert '' in commands.chk_cmd, ref
