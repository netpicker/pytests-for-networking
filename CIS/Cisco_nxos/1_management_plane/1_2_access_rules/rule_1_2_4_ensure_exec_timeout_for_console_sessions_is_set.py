from comfy.compliance import medium


@medium(
      name='rule_1_2_4_ensure_exec_timeout_for_console_sessions_is_set',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_2_4_ensure_exec_timeout_for_console_sessions_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
