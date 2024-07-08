from comfy.compliance import medium


@medium(
      name='rule_1_2_2_configure_ip_blocking_on_failed_logins',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_2_2_configure_ip_blocking_on_failed_logins(commands, ref):
    assert '' in commands.chk_cmd, ref
