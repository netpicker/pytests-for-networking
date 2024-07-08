from comfy.compliance import medium


@medium(
      name='rule_1_1_4_4_system_accounting',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_1_4_4_system_accounting(commands, ref):
    assert '' in commands.chk_cmd, ref
