from comfy.compliance import low


@low(
      name='rule_1_5_4_configure_snmp_traps',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_5_4_configure_snmp_traps(commands, ref):
    assert '' in commands.chk_cmd, ref
