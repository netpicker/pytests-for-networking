from comfy.compliance import low


@low(
      name='rule_4_7_2_ensure_authentication_is_set_to_aes_cmac',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_4_7_2_ensure_authentication_is_set_to_aes_cmac(commands, ref):
    assert '' in commands.chk_cmd, ref
