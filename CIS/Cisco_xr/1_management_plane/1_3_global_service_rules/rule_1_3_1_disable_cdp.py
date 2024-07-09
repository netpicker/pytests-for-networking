from comfy.compliance import medium


@medium(
      name='rule_1_3_1_disable_cdp',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='show cdp')
)
def rule_1_3_1_disable_cdp(commands, ref):
    assert 'CDP is not enabled' in commands.chk_cmd, ref
