from comfy.compliance import medium


@medium(
      name='rule_3_12_ensure_explicit_deny_in_access_lists_is_configured_correctly',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_3_12_ensure_explicit_deny_in_access_lists_is_configured_correctly(commands, ref):
    assert '' in commands.chk_cmd, ref
