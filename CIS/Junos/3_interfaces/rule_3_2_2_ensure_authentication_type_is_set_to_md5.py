from comfy.compliance import low


@low(
      name='rule_3_2_2_ensure_authentication_type_is_set_to_md5',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_3_2_2_ensure_authentication_type_is_set_to_md5(commands, ref):
    assert '' in commands.chk_cmd, ref
