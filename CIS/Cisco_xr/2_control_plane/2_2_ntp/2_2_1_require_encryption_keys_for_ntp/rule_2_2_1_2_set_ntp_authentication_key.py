from comfy.compliance import low


@low(
      name='rule_2_2_1_2_set_ntp_authentication_key',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_2_2_1_2_set_ntp_authentication_key(commands, ref):
    assert '' in commands.chk_cmd, ref
