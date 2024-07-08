from comfy.compliance import medium


@medium(
      name='rule_2_1_5_ensure_unused_interfaces_are_disabled',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_1_5_ensure_unused_interfaces_are_disabled(commands, ref):
    assert '' in commands.chk_cmd, ref
