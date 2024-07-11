from comfy.compliance import medium


@medium(
      name='rule_1_1_ensure_device_is_running_current_junos_software',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='show version | match JUNOS')
)
def rule_1_1_ensure_device_is_running_current_junos_software(commands, ref):
    assert '15.1X49-D150.2' in commands.chk_cmd, ref
