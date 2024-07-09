from comfy.compliance import medium


@medium(
      name='rule_1_2_2_set_modulus_to_greater_than_or_equal_to_2048_for_crypto_key_generate_rsa',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='sh crypto key mypubkey rsa')
)
def rule_1_2_2_set_modulus_to_greater_than_or_equal_to_2048_for_crypto_key_generate_rsa(commands, ref):
    assert 'Type : RSA General purpose' in commands.chk_cmd, ref
