from comfy.compliance import medium


@medium(
      name='rule_1_11_1_ensure_snmp_server_group_is_set_to_v3_priv',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_11_1_ensure_snmp_server_group_is_set_to_v3_priv(commands, ref):
    assert '' in commands.chk_cmd, ref
