from comfy.compliance import medium


@medium(
      name='rule_4_2_4_ensure_loose_authentication_check_is_not_configured',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_4_2_4_ensure_loose_authentication_check_is_not_configured(commands, ref):
    assert '' in commands.chk_cmd, ref
