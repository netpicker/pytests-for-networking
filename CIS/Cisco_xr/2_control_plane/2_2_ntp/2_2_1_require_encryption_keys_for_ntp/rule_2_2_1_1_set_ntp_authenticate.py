from comfy.compliance import low


@low(
      name='rule_2_2_1_1_set_ntp_authenticate',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_2_2_1_1_set_ntp_authenticate(commands, ref):
    assert '' in commands.chk_cmd, ref
