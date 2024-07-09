from comfy.compliance import low


@low(
      name='rule_1_6_2_log_all_successful_and_failed_administrative_logins',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_6_2_log_all_successful_and_failed_administrative_logins(commands, ref):
    assert '' in commands.chk_cmd, ref
