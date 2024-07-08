from comfy.compliance import medium


@medium(
      name='rule_2_5_3_ensure_client_authentication_is_secured',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_5_3_ensure_client_authentication_is_secured(commands, ref):
    assert '' in commands.chk_cmd, ref
