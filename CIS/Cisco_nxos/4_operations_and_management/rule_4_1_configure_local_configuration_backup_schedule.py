from comfy.compliance import medium


@medium(
      name='rule_4_1_configure_local_configuration_backup_schedule',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_4_1_configure_local_configuration_backup_schedule(commands, ref):
    assert '' in commands.chk_cmd, ref
