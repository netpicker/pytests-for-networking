from comfy.compliance import low


@low(
      name='rule_1_8_3_set_ssh_key_modulus_length',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_8_3_set_ssh_key_modulus_length(commands, ref):
    assert '' in commands.chk_cmd, ref
