from comfy.compliance import medium


@medium(
      name='rule_1_6_1_disable_telnet_access',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_6_1_disable_telnet_access(commands, ref):
    assert '' in commands.chk_cmd, ref
