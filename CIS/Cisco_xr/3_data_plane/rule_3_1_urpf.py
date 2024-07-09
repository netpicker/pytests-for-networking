from comfy.compliance import low


@low(
      name='rule_3_1_urpf',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_3_1_urpf(commands, ref):
    assert '' in commands.chk_cmd, ref
