from comfy.compliance import medium


@medium(
      name='rule_1_6_3_ensure_exec_timeout_for_console_sessions_is_set',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_6_3_ensure_exec_timeout_for_console_sessions_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
