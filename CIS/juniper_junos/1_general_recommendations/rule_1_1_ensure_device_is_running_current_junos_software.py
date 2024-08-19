from comfy.compliance import medium


@medium(
      name='rule_1_1_ensure_device_is_running_current_junos_software',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='show version')
)
def rule_1_1_ensure_device_is_running_current_junos_software(commands, ref):
    assert '21.4' in commands.chk_cmd, ref
