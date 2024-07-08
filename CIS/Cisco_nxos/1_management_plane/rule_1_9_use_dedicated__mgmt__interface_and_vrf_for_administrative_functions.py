from comfy.compliance import low


@low(
      name='rule_1_9_use_dedicated__mgmt__interface_and_vrf_for_administrative_functions',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_9_use_dedicated__mgmt__interface_and_vrf_for_administrative_functions(commands, ref):
    assert '' in commands.chk_cmd, ref
