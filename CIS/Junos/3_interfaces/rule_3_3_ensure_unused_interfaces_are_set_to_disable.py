from comfy.compliance import medium


@medium(
      name='rule_3_3_ensure_unused_interfaces_are_set_to_disable',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_3_3_ensure_unused_interfaces_are_set_to_disable(commands, ref):
    assert '' in commands.chk_cmd, ref
