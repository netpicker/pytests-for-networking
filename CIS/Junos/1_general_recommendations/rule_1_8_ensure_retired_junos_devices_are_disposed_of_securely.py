from comfy.compliance import medium


@medium(
      name='rule_1_8_ensure_retired_junos_devices_are_disposed_of_securely',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_1_8_ensure_retired_junos_devices_are_disposed_of_securely(commands, ref):
    assert '' in commands.chk_cmd, ref
