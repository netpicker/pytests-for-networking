from comfy.compliance import medium


@medium(
      name='rule_1_11_2_ensure_snmp_server_user_is_set_to_v3_auth_sha',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_11_2_ensure_snmp_server_user_is_set_to_v3_auth_sha(commands, ref):
    assert '' in commands.chk_cmd, ref
