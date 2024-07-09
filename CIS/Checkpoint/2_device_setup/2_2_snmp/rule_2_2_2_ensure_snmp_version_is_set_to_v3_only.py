from comfy.compliance import medium


@medium(
      name='rule_2_2_2_ensure_snmp_version_is_set_to_v3_only',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_2_2_ensure_snmp_version_is_set_to_v3_only(commands, ref):
    assert '' in commands.chk_cmd, ref
