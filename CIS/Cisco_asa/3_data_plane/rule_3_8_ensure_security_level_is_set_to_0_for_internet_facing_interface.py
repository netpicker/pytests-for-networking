from comfy.compliance import medium


@medium(
      name='rule_3_8_ensure_security_level_is_set_to_0_for_internet_facing_interface',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_3_8_ensure_security_level_is_set_to_0_for_internet_facing_interface(commands, ref):
    assert '' in commands.chk_cmd, ref
