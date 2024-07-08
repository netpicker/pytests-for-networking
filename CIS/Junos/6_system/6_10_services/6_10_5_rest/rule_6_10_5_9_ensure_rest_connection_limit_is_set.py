from comfy.compliance import medium


@medium(
      name='rule_6_10_5_9_ensure_rest_connection_limit_is_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_5_9_ensure_rest_connection_limit_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
