from comfy.compliance import medium


@medium(
      name='rule_6_10_6_ensure_telnet_is_not_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_6_ensure_telnet_is_not_set(commands, ref):
    assert '' in commands.chk_cmd, ref
