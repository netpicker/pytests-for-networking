from comfy.compliance import low


@low(
      name='rule_1_5_6_do_not_configure_a_read_write_snmp_community_string',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_5_6_do_not_configure_a_read_write_snmp_community_string(commands, ref):
    assert '' in commands.chk_cmd, ref
