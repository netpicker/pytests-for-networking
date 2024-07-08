from comfy.compliance import low


@low(
      name='rule_1_8_1_disable_power_on_auto_provisioning_poap',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_8_1_disable_power_on_auto_provisioning_poap(commands, ref):
    assert '' in commands.chk_cmd, ref
