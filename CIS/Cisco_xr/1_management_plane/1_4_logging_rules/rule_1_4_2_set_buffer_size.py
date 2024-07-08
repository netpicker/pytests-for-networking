from comfy.compliance import medium


@medium(
      name='rule_1_4_2_set_buffer_size',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_4_2_set_buffer_size(commands, ref):
    assert '' in commands.chk_cmd, ref
