from comfy.compliance import low


@low(
      name='rule_3_10_ensure_drop_out_of_state_tcp_packets_is_enabled',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_10_ensure_drop_out_of_state_tcp_packets_is_enabled(commands, ref):
    assert '' in commands.chk_cmd, ref
