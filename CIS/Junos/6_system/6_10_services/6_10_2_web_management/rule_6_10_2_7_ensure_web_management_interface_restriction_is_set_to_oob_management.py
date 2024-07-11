from comfy.compliance import low


@low(
      name='rule_6_10_2_7_ensure_web_management_interface_restriction_is_set_to_oob_management',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_2_7_ensure_web_management_interface_restriction_is_set_to_oob_management(commands, ref):
    assert '' in commands.chk_cmd, ref
