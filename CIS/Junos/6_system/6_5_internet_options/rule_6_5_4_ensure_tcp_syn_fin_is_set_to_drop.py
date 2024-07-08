from comfy.compliance import medium


@medium(
      name='rule_6_5_4_ensure_tcp_syn_fin_is_set_to_drop',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_5_4_ensure_tcp_syn_fin_is_set_to_drop(commands, ref):
    assert '' in commands.chk_cmd, ref
