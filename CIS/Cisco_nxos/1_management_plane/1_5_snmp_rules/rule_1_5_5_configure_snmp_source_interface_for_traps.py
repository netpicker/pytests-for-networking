from comfy.compliance import low


@low(
      name='rule_1_5_5_configure_snmp_source_interface_for_traps',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_5_5_configure_snmp_source_interface_for_traps(commands, ref):
    assert '' in commands.chk_cmd, ref
