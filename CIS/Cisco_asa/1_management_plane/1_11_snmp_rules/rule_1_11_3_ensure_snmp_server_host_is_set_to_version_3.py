from comfy.compliance import medium


@medium(
      name='rule_1_11_3_ensure_snmp_server_host_is_set_to_version_3',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_11_3_ensure_snmp_server_host_is_set_to_version_3(commands, ref):
    assert '' in commands.chk_cmd, ref
