from comfy.compliance import low


@low(
      name='rule_1_8_2_disable_ipxe_pre_boot_execution_environment',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_8_2_disable_ipxe_pre_boot_execution_environment(commands, ref):
    assert '' in commands.chk_cmd, ref
