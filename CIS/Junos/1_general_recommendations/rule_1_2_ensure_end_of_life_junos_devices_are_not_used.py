from comfy.compliance import medium


@medium(
      name='rule_1_2_ensure_end_of_life_junos_devices_are_not_used',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_1_2_ensure_end_of_life_junos_devices_are_not_used(commands, ref):
    assert '' in commands.chk_cmd, ref
