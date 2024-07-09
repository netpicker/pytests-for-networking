from comfy.compliance import medium


@medium(
      name='rule_1_2_5_ensure_exec_timeout_for_remote_administrative_sessions_vty_is_set',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_2_5_ensure_exec_timeout_for_remote_administrative_sessions_vty_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
