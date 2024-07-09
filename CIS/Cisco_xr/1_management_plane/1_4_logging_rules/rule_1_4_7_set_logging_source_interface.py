from comfy.compliance import medium


@medium(
      name='rule_1_4_7_set_logging_source_interface',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_4_7_set_logging_source_interface(commands, ref):
    assert '' in commands.chk_cmd, ref
