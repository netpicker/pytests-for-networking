from comfy.compliance import low


@low(
      name='rule_4_6_2_ensure_bfd_authentication_is_not_set_to_loose_check',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_4_6_2_ensure_bfd_authentication_is_not_set_to_loose_check(commands, ref):
    assert '' in commands.chk_cmd, ref
