from comfy.compliance import low


@low(
      name='rule_2_1_6_key_chains',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_2_1_6_key_chains(commands, ref):
    assert '' in commands.chk_cmd, ref
