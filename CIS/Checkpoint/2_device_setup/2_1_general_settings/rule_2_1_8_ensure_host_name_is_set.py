from comfy.compliance import medium


@medium(
      name='rule_2_1_8_ensure_host_name_is_set',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_1_8_ensure_host_name_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
