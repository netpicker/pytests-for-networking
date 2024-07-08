from comfy.compliance import medium


@medium(
      name='rule_1_2_3_set_seconds_for_ssh_timeout_for_60_seconds_or_less',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='sh running-config ssh timeout')
)
def rule_1_2_3_set_seconds_for_ssh_timeout_for_60_seconds_or_less(commands, ref):
    assert 'ssh timeout' in commands.chk_cmd, ref
