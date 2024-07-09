from comfy.compliance import medium


@medium(
      name='rule_1_7_1_configure_at_least_2_external_ntp_servers',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_7_1_configure_at_least_2_external_ntp_servers(commands, ref):
    assert '' in commands.chk_cmd, ref
