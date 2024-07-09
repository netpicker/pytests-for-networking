from comfy.compliance import medium


@medium(
      name='rule_2_4_3_configuring_scheduled_backups',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_4_3_configuring_scheduled_backups(commands, ref):
    assert '' in commands.chk_cmd, ref
