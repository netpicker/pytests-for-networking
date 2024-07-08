from comfy.compliance import medium


@medium(
      name='rule_1_11_ensure_deny_access_after_failed_login_attempts_is_selected',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_11_ensure_deny_access_after_failed_login_attempts_is_selected(commands, ref):
    assert '' in commands.chk_cmd, ref
