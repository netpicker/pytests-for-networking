from comfy.compliance import medium


@medium(
      name='rule_2_2_3_ensure_snmp_traps_is_enabled',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_2_3_ensure_snmp_traps_is_enabled(commands, ref):
    assert '' in commands.chk_cmd, ref
