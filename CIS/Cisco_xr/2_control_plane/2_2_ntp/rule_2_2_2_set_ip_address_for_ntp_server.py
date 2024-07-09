from comfy.compliance import medium


@medium(
      name='rule_2_2_2_set_ip_address_for_ntp_server',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_2_2_2_set_ip_address_for_ntp_server(commands, ref):
    assert '' in commands.chk_cmd, ref
