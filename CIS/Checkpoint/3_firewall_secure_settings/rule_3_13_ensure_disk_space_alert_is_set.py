from comfy.compliance import medium


@medium(
      name='rule_3_13_ensure_disk_space_alert_is_set',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_13_ensure_disk_space_alert_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
