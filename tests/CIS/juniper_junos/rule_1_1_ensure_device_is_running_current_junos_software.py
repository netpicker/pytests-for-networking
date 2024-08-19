from comfy.compliance import medium


@medium(
      name='rule_1_1_ensure_device_is_running_current_junos_software',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_1_1_ensure_device_is_running_current_junos_software(commands, ref):
    assert '' in commands.chk_cmd, ref
