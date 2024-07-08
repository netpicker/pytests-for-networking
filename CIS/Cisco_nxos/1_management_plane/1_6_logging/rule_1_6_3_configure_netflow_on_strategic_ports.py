from comfy.compliance import low


@low(
      name='rule_1_6_3_configure_netflow_on_strategic_ports',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_6_3_configure_netflow_on_strategic_ports(commands, ref):
    assert '' in commands.chk_cmd, ref
