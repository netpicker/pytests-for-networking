from comfy.compliance import medium


@medium(
      name='rule_2_1_9_ensure_telnet_is_disabled',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_1_9_ensure_telnet_is_disabled(commands, ref):
    assert '' in commands.chk_cmd, ref
