from comfy.compliance import medium


@medium(
      name='rule_6_10_2_6_ensure_web_management_interface_restriction_is_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_2_6_ensure_web_management_interface_restriction_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
