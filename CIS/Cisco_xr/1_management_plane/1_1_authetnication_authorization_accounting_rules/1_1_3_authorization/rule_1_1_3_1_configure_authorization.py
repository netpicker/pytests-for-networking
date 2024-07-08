from comfy.compliance import low


@low(
      name='rule_1_1_3_1_configure_authorization',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_1_3_1_configure_authorization(commands, ref):
    assert '' in commands.chk_cmd, ref
