from comfy.compliance import low


@low(
      name='rule_4_3_configure_alerts_on_all_configuration_changes',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_4_3_configure_alerts_on_all_configuration_changes(commands, ref):
    assert '' in commands.chk_cmd, ref
