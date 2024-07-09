from comfy.compliance import medium


@medium(
      name='rule_1_7_2_ensure_tls_1_2_is_set_for_https_access',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_7_2_ensure_tls_1_2_is_set_for_https_access(commands, ref):
    assert '' in commands.chk_cmd, ref
