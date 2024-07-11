from comfy.compliance import medium


@medium(
      name='rule_3_4_ensure_interface_description_is_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_3_4_ensure_interface_description_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
