from comfy.compliance import low


@low(
      name='rule_4_6_1_ensure_bfd_authentication_is_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_4_6_1_ensure_bfd_authentication_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
