from comfy.compliance import medium


@medium(
      name='rule_6_10_1_3_ensure_ssh_connection_limit_is_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_1_3_ensure_ssh_connection_limit_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
