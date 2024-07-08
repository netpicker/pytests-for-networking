from comfy.compliance import low


@low(
      name='rule_1_7_4_configure_ntp_authentication',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_7_4_configure_ntp_authentication(commands, ref):
    assert '' in commands.chk_cmd, ref
