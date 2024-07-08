from comfy.compliance import low


@low(
      name='rule_1_5_3_configure_snmpv3',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_5_3_configure_snmpv3(commands, ref):
    assert '' in commands.chk_cmd, ref
