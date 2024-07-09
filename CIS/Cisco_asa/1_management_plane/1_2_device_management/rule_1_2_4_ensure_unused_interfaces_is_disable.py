from comfy.compliance import medium


@medium(
      name='rule_1_2_4_ensure_unused_interfaces_is_disable',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_2_4_ensure_unused_interfaces_is_disable(commands, ref):
    assert '' in commands.chk_cmd, ref
