from comfy.compliance import medium


@medium(
      name='rule_6_5_3_ensure_icmp_source_quench_is_set_to_disabled',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_5_3_ensure_icmp_source_quench_is_set_to_disabled(commands, ref):
    assert '' in commands.chk_cmd, ref
