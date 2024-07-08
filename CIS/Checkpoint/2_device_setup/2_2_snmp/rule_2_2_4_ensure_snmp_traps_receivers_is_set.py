from comfy.compliance import medium


@medium(
      name='rule_2_2_4_ensure_snmp_traps_receivers_is_set',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_2_4_ensure_snmp_traps_receivers_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
