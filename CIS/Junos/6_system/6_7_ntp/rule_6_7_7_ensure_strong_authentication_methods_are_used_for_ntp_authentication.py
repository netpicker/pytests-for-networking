from comfy.compliance import low


@low(
      name='rule_6_7_7_ensure_strong_authentication_methods_are_used_for_ntp_authentication',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_7_7_ensure_strong_authentication_methods_are_used_for_ntp_authentication(commands, ref):
    assert '' in commands.chk_cmd, ref
