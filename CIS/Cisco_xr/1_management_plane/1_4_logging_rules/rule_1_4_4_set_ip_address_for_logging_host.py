from comfy.compliance import medium


@medium(
      name='rule_1_4_4_set_ip_address_for_logging_host',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_4_4_set_ip_address_for_logging_host(commands, ref):
    assert '' in commands.chk_cmd, ref
