from comfy.compliance import medium


@medium(
      name='rule_1_1_4_3_network_accounting',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_1_4_3_network_accounting(commands, ref):
    assert '' in commands.chk_cmd, ref
