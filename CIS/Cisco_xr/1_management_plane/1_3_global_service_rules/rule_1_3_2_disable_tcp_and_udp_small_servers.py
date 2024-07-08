from comfy.compliance import medium


@medium(
      name='rule_1_3_2_disable_tcp_and_udp_small_servers',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='show run | incl small')
)
def rule_1_3_2_disable_tcp_and_udp_small_servers(commands, ref):
    assert '' in commands.chk_cmd, ref
