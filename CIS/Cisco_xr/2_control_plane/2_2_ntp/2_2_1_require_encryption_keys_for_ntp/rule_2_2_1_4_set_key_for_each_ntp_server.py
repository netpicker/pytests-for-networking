from comfy.compliance import low


@low(
      name='rule_2_2_1_4_set_key_for_each_ntp_server',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_2_2_1_4_set_key_for_each_ntp_server(commands, ref):
    assert '' in commands.chk_cmd, ref
