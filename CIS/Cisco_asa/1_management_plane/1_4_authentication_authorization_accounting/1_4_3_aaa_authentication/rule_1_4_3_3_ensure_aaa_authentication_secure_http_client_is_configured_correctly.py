from comfy.compliance import medium


@medium(
      name='rule_1_4_3_3_ensure_aaa_authentication_secure_http_client_is_configured_correctly',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_4_3_3_ensure_aaa_authentication_secure_http_client_is_configured_correctly(commands, ref):
    assert '' in commands.chk_cmd, ref
