from comfy.compliance import medium


@medium(
      name='rule_1_8_ensure_deny_access_to_unused_accounts_is_selected',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_8_ensure_deny_access_to_unused_accounts_is_selected(commands, ref):
    assert '' in commands.chk_cmd, ref
