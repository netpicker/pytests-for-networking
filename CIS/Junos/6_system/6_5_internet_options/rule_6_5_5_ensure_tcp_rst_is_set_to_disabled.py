from comfy.compliance import medium


@medium(
      name='rule_6_5_5_ensure_tcp_rst_is_set_to_disabled',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_5_5_ensure_tcp_rst_is_set_to_disabled(commands, ref):
    assert '' in commands.chk_cmd, ref
